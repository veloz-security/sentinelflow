// Package ai implements SentinelFlow's fail-closed OpenAI transport boundary.
package ai

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const (
	Model            = "gpt-5.6-sol"
	ResponsesPath    = "/v1/responses"
	ReasoningEffort  = "medium"
	MaxInputBytes    = 12 * 1024
	MaxEvidenceRefs  = 50
	MaxOutputTokens  = 2048
	RequestTimeout   = 30 * time.Second
	MaxConcurrency   = 2
	maxResponseBytes = 1 << 20
	retryDelay       = 100 * time.Millisecond

	OpenAIResponsesAdapterID   = "openai-responses-v1"
	DeterministicStubAdapterID = "sentinelflow-deterministic-ai-stub-v1"
)

type ProviderKind string

const (
	ProviderOpenAIResponses   ProviderKind = "openai_responses"
	ProviderDeterministicStub ProviderKind = "deterministic_stub"
)

var providerIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ProviderIdentity is an immutable-by-construction description of the exact
// analyzer adapter selected for one worker runtime. Its fields are private so
// callers cannot relabel a returned identity in place.
type ProviderIdentity struct {
	kind            ProviderKind
	adapterID       string
	model           string
	reasoningEffort string
	rateCardVersion string
}

func NewOpenAIResponsesIdentity(rateCardVersion string) (ProviderIdentity, bool) {
	return ParseProviderIdentity(
		string(ProviderOpenAIResponses), OpenAIResponsesAdapterID,
		Model, ReasoningEffort, rateCardVersion,
	)
}

func DeterministicStubIdentity() ProviderIdentity {
	identity, _ := ParseProviderIdentity(
		string(ProviderDeterministicStub), DeterministicStubAdapterID, "", "", "",
	)
	return identity
}

func ParseProviderIdentity(
	kind, adapterID, model, reasoningEffort, rateCardVersion string,
) (ProviderIdentity, bool) {
	identity := ProviderIdentity{
		kind: ProviderKind(kind), adapterID: adapterID, model: model,
		reasoningEffort: reasoningEffort, rateCardVersion: rateCardVersion,
	}
	if !providerIdentifierPattern.MatchString(adapterID) {
		return ProviderIdentity{}, false
	}
	switch identity.kind {
	case ProviderOpenAIResponses:
		if adapterID != OpenAIResponsesAdapterID || model != Model ||
			reasoningEffort != ReasoningEffort ||
			!providerIdentifierPattern.MatchString(rateCardVersion) {
			return ProviderIdentity{}, false
		}
	case ProviderDeterministicStub:
		if adapterID != DeterministicStubAdapterID || model != "" ||
			reasoningEffort != "" || rateCardVersion != "" {
			return ProviderIdentity{}, false
		}
	default:
		return ProviderIdentity{}, false
	}
	return identity, true
}

func (identity ProviderIdentity) Kind() ProviderKind                { return identity.kind }
func (identity ProviderIdentity) AdapterID() string                 { return identity.adapterID }
func (identity ProviderIdentity) Model() string                     { return identity.model }
func (identity ProviderIdentity) ReasoningEffort() string           { return identity.reasoningEffort }
func (identity ProviderIdentity) RateCardVersion() string           { return identity.rateCardVersion }
func (identity ProviderIdentity) IsZero() bool                      { return identity == ProviderIdentity{} }
func (identity ProviderIdentity) Equal(other ProviderIdentity) bool { return identity == other }

type FailureReason string

const (
	FailureBudgetExhausted FailureReason = "budget_exhausted"
	FailureInputTooLarge   FailureReason = "input_too_large"
	FailureNetworkError    FailureReason = "network_error"
	FailureHTTP408         FailureReason = "http_408"
	FailureHTTP409         FailureReason = "http_409"
	FailureRateLimited     FailureReason = "rate_limited"
	FailureServerError     FailureReason = "server_error"
	FailureTimeout         FailureReason = "timeout"
	FailureRefused         FailureReason = "refused"
	FailureIncomplete      FailureReason = "incomplete"
	FailureSchemaInvalid   FailureReason = "schema_invalid"
	FailureEvidenceInvalid FailureReason = "evidence_invalid"
	FailureCancelled       FailureReason = "cancelled"
	FailureConfiguration   FailureReason = "configuration_error"
)

// Failure deliberately contains no provider body, input, key, or wrapped
// parser/transport error. It is safe for logs and persisted failure state.
type Failure struct {
	Reason     FailureReason
	StatusCode int
	Attempts   int
}

func (f *Failure) Error() string {
	if f == nil {
		return "openai analysis failed"
	}
	return "openai analysis failed: " + string(f.Reason)
}

func FailureOf(err error) (*Failure, bool) {
	var failure *Failure
	ok := errors.As(err, &failure)
	return failure, ok
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func (realClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ErrBudgetExhausted is the only budget error mapped to budget_exhausted.
// All other budget errors become configuration_error without exposing text.
var ErrBudgetExhausted = errors.New("operator AI budget exhausted")

type BudgetRequest struct {
	Model              string
	RateCardVersion    string
	MaxInputTokenUnits int
	MaxOutputTokens    int
	ReservedAt         time.Time
}

type Usage struct {
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
	Trusted           bool
}

type BudgetReservation interface {
	// Settle charges the full conservative reservation when fullCharge is true.
	Settle(context.Context, Usage, bool) error
}

type BudgetGate interface {
	Reserve(context.Context, BudgetRequest) (BudgetReservation, error)
}

type Result struct {
	ResponseID         string
	Output             []byte
	Usage              Usage
	Attempts           int
	InputDigest        string
	InputSchemaDigest  string
	PromptDigest       string
	OutputSchemaDigest string
}
