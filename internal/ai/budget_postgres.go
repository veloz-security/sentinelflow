package ai

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"regexp"

	"github.com/jackc/pgx/v5"
)

const microUSDPerMillion = int64(1_000_000)

var (
	budgetIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	errBudgetPersistence    = errors.New("AI budget persistence failed")
)

const reserveAIBudgetSQL = `
SELECT reservation_id::text, reserved_micro_usd, state
FROM sentinelflow.reserve_ai_budget($1::uuid, $2, $3, $4, $5)`

const settleAIBudgetSQL = `
SELECT reservation_id::text, charged_micro_usd, state
FROM sentinelflow.settle_ai_budget($1::uuid, $2)`

type budgetQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PostgreSQLBudgetConfig uses integer micro-USD rates. Values are operator
// inputs, not provider price claims, and are versioned outside this package.
type PostgreSQLBudgetConfig struct {
	Model                         string
	RateCardVersion               string
	DailyLimitMicroUSD            int64
	InputMicroUSDPerMillion       int64
	CachedInputMicroUSDPerMillion int64
	OutputMicroUSDPerMillion      int64
}

// PostgreSQLBudgetGate atomically reserves worst-case cost before a request.
// PostgreSQL's UTC date and clock are authoritative; caller wall time cannot
// select a cheaper day or release an expired reservation.
type PostgreSQLBudgetGate struct {
	db                            budgetQueryRower
	model                         string
	rateCardVersion               string
	dailyLimitMicroUSD            int64
	inputMicroUSDPerMillion       int64
	cachedInputMicroUSDPerMillion int64
	outputMicroUSDPerMillion      int64
	newReservationID              func() (string, error)
}

func NewPostgreSQLBudgetGate(db budgetQueryRower, config PostgreSQLBudgetConfig) (*PostgreSQLBudgetGate, error) {
	if db == nil || !budgetIdentifierPattern.MatchString(config.Model) ||
		!budgetIdentifierPattern.MatchString(config.RateCardVersion) ||
		config.DailyLimitMicroUSD <= 0 || config.DailyLimitMicroUSD > 1_000_000_000_000 ||
		config.InputMicroUSDPerMillion <= 0 || config.CachedInputMicroUSDPerMillion <= 0 ||
		config.OutputMicroUSDPerMillion <= 0 {
		return nil, errBudgetPersistence
	}
	return &PostgreSQLBudgetGate{
		db: db, model: config.Model, rateCardVersion: config.RateCardVersion,
		dailyLimitMicroUSD:            config.DailyLimitMicroUSD,
		inputMicroUSDPerMillion:       config.InputMicroUSDPerMillion,
		cachedInputMicroUSDPerMillion: config.CachedInputMicroUSDPerMillion,
		outputMicroUSDPerMillion:      config.OutputMicroUSDPerMillion,
		newReservationID:              newBudgetReservationID,
	}, nil
}

func (g *PostgreSQLBudgetGate) Reserve(ctx context.Context, request BudgetRequest) (BudgetReservation, error) {
	if g == nil || ctx == nil || request.Model != g.model ||
		request.RateCardVersion != g.rateCardVersion || request.ReservedAt.IsZero() ||
		request.MaxInputTokenUnits != MaxInputBytes || request.MaxOutputTokens != MaxOutputTokens {
		return nil, errBudgetPersistence
	}
	inputRate := g.inputMicroUSDPerMillion
	if g.cachedInputMicroUSDPerMillion > inputRate {
		inputRate = g.cachedInputMicroUSDPerMillion
	}
	reserved, err := roundedMicroUSDCost([]costTerm{
		{units: int64(request.MaxInputTokenUnits), rate: inputRate},
		{units: int64(request.MaxOutputTokens), rate: g.outputMicroUSDPerMillion},
	})
	if err != nil {
		return nil, errBudgetPersistence
	}
	if reserved > g.dailyLimitMicroUSD {
		return nil, ErrBudgetExhausted
	}
	reservationID, err := g.newReservationID()
	if err != nil {
		return nil, errBudgetPersistence
	}

	var returnedID, state string
	var returnedReserved int64
	err = g.db.QueryRow(ctx, reserveAIBudgetSQL,
		reservationID, g.model, g.rateCardVersion,
		g.dailyLimitMicroUSD, reserved,
	).Scan(&returnedID, &returnedReserved, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBudgetExhausted
	}
	if err != nil || returnedID != reservationID || returnedReserved != reserved || state != "active" {
		return nil, errBudgetPersistence
	}
	return &postgresBudgetReservation{
		gate: g, reservationID: reservationID, reservedMicroUSD: reserved,
	}, nil
}

type postgresBudgetReservation struct {
	gate             *PostgreSQLBudgetGate
	reservationID    string
	reservedMicroUSD int64
}

func (r *postgresBudgetReservation) Settle(ctx context.Context, usage Usage, fullCharge bool) error {
	if r == nil || r.gate == nil || ctx == nil || r.reservationID == "" || r.reservedMicroUSD <= 0 {
		return errBudgetPersistence
	}
	charged := r.reservedMicroUSD
	if !fullCharge {
		if !usage.Trusted || usage.InputTokens <= 0 || usage.OutputTokens <= 0 ||
			usage.CachedInputTokens < 0 || usage.CachedInputTokens > usage.InputTokens ||
			usage.InputTokens > MaxInputBytes || usage.OutputTokens > MaxOutputTokens {
			return r.settleFullAndFail(ctx)
		}
		noncached := usage.InputTokens - usage.CachedInputTokens
		var err error
		charged, err = roundedMicroUSDCost([]costTerm{
			{units: noncached, rate: r.gate.inputMicroUSDPerMillion},
			{units: usage.CachedInputTokens, rate: r.gate.cachedInputMicroUSDPerMillion},
			{units: usage.OutputTokens, rate: r.gate.outputMicroUSDPerMillion},
		})
		if err != nil || charged <= 0 || charged > r.reservedMicroUSD {
			return r.settleFullAndFail(ctx)
		}
	}
	return r.settle(ctx, charged)
}

func (r *postgresBudgetReservation) settleFullAndFail(ctx context.Context) error {
	_ = r.settle(ctx, r.reservedMicroUSD)
	return errBudgetPersistence
}

func (r *postgresBudgetReservation) settle(ctx context.Context, charged int64) error {
	var returnedID, state string
	var returnedCharge int64
	err := r.gate.db.QueryRow(ctx, settleAIBudgetSQL,
		r.reservationID, charged,
	).Scan(&returnedID, &returnedCharge, &state)
	if err != nil || returnedID != r.reservationID || returnedCharge != charged || state != "settled" {
		return errBudgetPersistence
	}
	return nil
}

type costTerm struct {
	units int64
	rate  int64
}

func roundedMicroUSDCost(terms []costTerm) (int64, error) {
	total := new(big.Int)
	for _, term := range terms {
		if term.units < 0 || term.rate <= 0 {
			return 0, errBudgetPersistence
		}
		product := new(big.Int).Mul(big.NewInt(term.units), big.NewInt(term.rate))
		total.Add(total, product)
	}
	if total.Sign() <= 0 {
		return 0, errBudgetPersistence
	}
	total.Add(total, big.NewInt(microUSDPerMillion-1))
	total.Quo(total, big.NewInt(microUSDPerMillion))
	if !total.IsInt64() {
		return 0, errBudgetPersistence
	}
	return total.Int64(), nil
}

func newBudgetReservationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	raw := hex.EncodeToString(value[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}

// MicroUSDPerMillion converts an operator-provided USD-per-million rate into
// the ledger's fixed integer precision, rounding upward so conversion cannot
// under-reserve. It is intended for validated finite configuration values.
func MicroUSDPerMillion(rate float64) (int64, error) {
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate <= 0 || rate > 1_000_000 {
		return 0, errBudgetPersistence
	}
	value := math.Ceil(rate * float64(microUSDPerMillion))
	if value <= 0 || value > math.MaxInt64 {
		return 0, errBudgetPersistence
	}
	return int64(value), nil
}

// DailyLimitMicroUSD converts the configured USD daily guardrail to the same
// fixed precision, rounding down so floating-point input cannot raise a limit.
func DailyLimitMicroUSD(limit float64) (int64, error) {
	if math.IsNaN(limit) || math.IsInf(limit, 0) || limit <= 0 || limit > 1_000_000 {
		return 0, errBudgetPersistence
	}
	value := math.Floor(limit * float64(microUSDPerMillion))
	if value <= 0 || value > 1_000_000_000_000 {
		return 0, errBudgetPersistence
	}
	return int64(value), nil
}

var _ BudgetGate = (*PostgreSQLBudgetGate)(nil)
var _ BudgetReservation = (*postgresBudgetReservation)(nil)
