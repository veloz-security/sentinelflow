package demohistoryimport

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const rollbackTimeout = 5 * time.Second

var gatewayBatchIDs = [...]string{
	"019b0000-0000-7000-8000-000000000201",
	"019b0000-0000-7000-8000-000000000202",
	"019b0000-0000-7000-8000-000000000203",
}

const authBatchID = "019b0000-0000-7000-8000-000000000204"

type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type Importer struct {
	db       TransactionBeginner
	reader   DatasetReader
	verifier validation.DemoHistoryManifestVerifier
	fault    func(stage string, ordinal int) error
}

func New(
	db TransactionBeginner,
	reader DatasetReader,
	verifier validation.DemoHistoryManifestVerifier,
) (*Importer, error) {
	if db == nil || reader == nil || verifier == nil {
		return nil, reject(ErrorConfiguration)
	}
	return &Importer{db: db, reader: reader, verifier: verifier}, nil
}

// Import re-verifies the signed manifest on every call. A completed SQL ledger
// can return a historical result only after that fresh opaque binding exists
// and PostgreSQL revalidates the mapped canonical rows.
func (i *Importer) Import(ctx context.Context, signedManifestEnvelope []byte) (Result, error) {
	if i == nil || ctx == nil {
		return Result{}, reject(ErrorConfiguration)
	}
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	raw, err := i.reader.ReadPinnedDataset(ctx)
	if err != nil {
		return Result{}, reject(ErrorSource)
	}
	dataset, err := demohistory.Load(raw)
	if err != nil {
		return Result{}, reject(ErrorDataset)
	}
	claims, err := verifyManifest(ctx, i.verifier, signedManifestEnvelope, dataset)
	if err != nil {
		return Result{}, err
	}

	tx, err := i.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
		}
	}()

	failed := func(cause error) (Result, error) {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		_ = tx.Rollback(rollbackCtx)
		cancel()
		committed = true
		code := classifyCode(ctx, cause)
		i.recordFailure(dataset, claims, code)
		return Result{}, reject(code)
	}

	if _, err = tx.Exec(ctx, lockImportSQL); err != nil {
		return failed(err)
	}
	var disposition string
	if err = tx.QueryRow(ctx, beginImportSQL, importClaimArguments(dataset, claims)...).Scan(&disposition); err != nil {
		return failed(err)
	}
	if disposition == "historical" {
		result, readErr := readResult(ctx, tx, claims.importID)
		if readErr != nil {
			return failed(readErr)
		}
		result.disposition = DispositionHistorical
		result.verifiedBinding = claims.verifiedBinding
		if err = verifyResultBinding(result, dataset, claims); err != nil {
			return failed(err)
		}
		if err = tx.Commit(ctx); err != nil {
			return Result{}, classify(ctx, err)
		}
		committed = true
		return result, nil
	}
	if disposition != "started" {
		return failed(errors.New("unexpected import disposition"))
	}
	if err = i.inject("after_begin", 0); err != nil {
		return failed(err)
	}

	gatewaySequence, authSequence := 0, 0
	for ordinal, record := range dataset.Records() {
		switch record.Kind() {
		case demohistory.RecordGatewayHTTP:
			gatewaySequence++
			event, ok := record.GatewayHTTP()
			if !ok || gatewaySequence > len(gatewayBatchIDs) {
				return failed(errors.New("invalid gateway projection"))
			}
			batch, batchErr := syntheticBatch("gateway-demo", "IiIiIiIiIiIiIiIiIiIiIg",
				gatewayBatchIDs[gatewaySequence-1], uint64(gatewaySequence), event.CompletedAt.Time(), event)
			if batchErr != nil {
				return failed(batchErr)
			}
			if _, err = tx.Exec(ctx, appendGatewaySQL,
				claims.importID, batch.senderEpoch, gatewaySequence, batch.batchID,
				batch.digest, batch.size, event.EventID, event.IdempotencyKey,
				event.RequestID, event.TraceID, event.StartedAt.Time(), event.CompletedAt.Time(),
				event.SourceIP, event.Method, event.Protocol, event.RouteLabel,
				event.PathCatalogVersion, string(event.SuspiciousPathID), event.Host,
				event.ServiceLabel, event.StatusCode, int64(event.RequestBytes),
				int64(event.ResponseBytes), int32(event.LatencyMS),
			); err != nil {
				return failed(err)
			}
		case demohistory.RecordAuthEvent:
			authSequence++
			event, ok := record.AuthEvent()
			if !ok || authSequence != 1 {
				return failed(errors.New("invalid auth projection"))
			}
			batch, batchErr := syntheticBatch("auth-demo", "EREREREREREREREREREREQ",
				authBatchID, uint64(authSequence), event.OccurredAt.Time(), event)
			if batchErr != nil {
				return failed(batchErr)
			}
			if _, err = tx.Exec(ctx, appendAuthSQL,
				claims.importID, batch.senderEpoch, authSequence, batch.batchID,
				batch.digest, batch.size, event.EventID, event.IdempotencyKey,
				event.GatewayRequestID, event.TraceID, event.OccurredAt.Time(),
				event.SourceIP, event.ServiceLabel, event.RouteLabel,
				event.AccountHash, string(event.Outcome),
			); err != nil {
				return failed(err)
			}
		default:
			return failed(errors.New("invalid record kind"))
		}
		if err = i.inject("after_record", ordinal+1); err != nil {
			return failed(err)
		}
	}
	if gatewaySequence != 3 || authSequence != 1 {
		return failed(errors.New("invalid record cardinality"))
	}

	for ordinal, coverage := range dataset.SourceCoverage() {
		endpoint := ""
		switch coverage.SenderID() {
		case "gateway-demo":
			endpoint = "gateway"
		case "auth-demo":
			endpoint = "auth"
		default:
			return failed(errors.New("unknown source coverage sender"))
		}
		if _, err = tx.Exec(ctx, appendCoverageSQL,
			claims.importID, coverage.SenderID(), endpoint, coverage.SenderEpoch(),
			coverage.CoverageStart(), coverage.CoverageEnd(),
			int64(coverage.FirstSequence()), int64(coverage.LastSequence()),
		); err != nil {
			return failed(err)
		}
		if err = i.inject("after_coverage", ordinal+1); err != nil {
			return failed(err)
		}
	}
	if err = i.inject("before_complete", 0); err != nil {
		return failed(err)
	}
	if _, err = tx.Exec(ctx, completeImportSQL, claims.importID); err != nil {
		return failed(err)
	}
	if _, err = tx.Exec(ctx, forceConstraintsSQL); err != nil {
		return failed(err)
	}
	result, err := readResult(ctx, tx, claims.importID)
	if err != nil {
		return failed(err)
	}
	result.disposition = DispositionApplied
	result.verifiedBinding = claims.verifiedBinding
	if err = verifyResultBinding(result, dataset, claims); err != nil {
		return failed(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return Result{}, classify(ctx, err)
	}
	committed = true
	return result, nil
}

// ImportOrAttachExisting supports same-run process restart without turning a
// stale proof into import authority. It first validates the immutable signed
// contract, then reads the exact completed append-only ledger under the same
// advisory lock. Only unequivocal absence falls through to Import, which
// re-runs the strict freshness verifier immediately before mutation.
func (i *Importer) ImportOrAttachExisting(
	ctx context.Context,
	signedManifestEnvelope []byte,
) (Result, error) {
	if i == nil || ctx == nil {
		return Result{}, reject(ErrorConfiguration)
	}
	raw, err := i.reader.ReadPinnedDataset(ctx)
	if err != nil {
		return Result{}, reject(ErrorSource)
	}
	dataset, err := demohistory.Load(raw)
	clear(raw)
	if err != nil {
		return Result{}, reject(ErrorDataset)
	}
	claims, err := verifyManifestImmutable(ctx, i.verifier, signedManifestEnvelope, dataset)
	if err != nil {
		return Result{}, err
	}
	tx, err := i.db.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	finished := false
	defer func() {
		if !finished {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
		}
	}()
	if _, err = tx.Exec(ctx, lockImportSQL); err != nil {
		return Result{}, classify(ctx, err)
	}
	result, err := readRecoveryResult(ctx, tx, claims.importID)
	if errors.Is(err, pgx.ErrNoRows) {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			return Result{}, classify(ctx, rollbackErr)
		}
		finished = true
		return i.importFreshOrHistorical(ctx, signedManifestEnvelope)
	}
	if err != nil || verifyRecoveryIdentity(result, dataset, claims) != nil {
		return Result{}, reject(ErrorBinding)
	}
	if result.status == "failed" {
		if result.failureCode == "" || result.completedAt.IsZero() ||
			result.gatewayRecordCount != 0 || result.authRecordCount != 0 ||
			result.sourceCoverageCount != 0 || result.recoveryRowsValid ||
			result.recoveryGatewayRows != 0 || result.recoveryAuthRows != 0 ||
			result.recoveryCoverageRows != 0 {
			return Result{}, reject(ErrorBinding)
		}
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			return Result{}, classify(ctx, rollbackErr)
		}
		finished = true
		// A failed ledger row has no authority to bypass freshness. Import will
		// re-verify freshness, reacquire the lock, and atomically transition the
		// exact failed identity back to importing.
		return i.importFreshOrHistorical(ctx, signedManifestEnvelope)
	}
	if !result.recoveryRowsValid || result.recoveryGatewayRows != 3 ||
		result.recoveryAuthRows != 1 || result.recoveryCoverageRows != 2 ||
		verifyHistoricalResultBinding(result, dataset, claims) != nil {
		return Result{}, reject(ErrorBinding)
	}
	result.disposition = DispositionHistorical
	if err = tx.Commit(ctx); err != nil {
		return Result{}, classify(ctx, err)
	}
	finished = true
	return result, nil
}

func (i *Importer) importFreshOrHistorical(ctx context.Context, envelope []byte) (Result, error) {
	result, err := i.Import(ctx, envelope)
	if err != nil {
		return Result{}, err
	}
	if result.disposition == DispositionHistorical {
		// ImportOrAttachExisting has a deliberately sharper result contract than
		// Import: historical completion is content-only recovery evidence and
		// never carries the fresh runtime-capable binding minted during a race.
		result.verifiedBinding = validation.VerifiedDemoHistoryBinding{}
	}
	return result, nil
}

func (i *Importer) inject(stage string, ordinal int) error {
	if i.fault == nil {
		return nil
	}
	if err := i.fault(stage, ordinal); err != nil {
		return reject(ErrorFaultInjected)
	}
	return nil
}

type syntheticBatchMaterial struct {
	senderEpoch string
	batchID     string
	digest      string
	size        int
}

func syntheticBatch(senderID, senderEpoch, batchID string, sequence uint64, sentAt time.Time, record any) (syntheticBatchMaterial, error) {
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return syntheticBatchMaterial{}, err
	}
	wire := struct {
		SchemaVersion string            `json:"schema_version"`
		SenderID      string            `json:"sender_id"`
		SenderEpoch   string            `json:"sender_epoch"`
		BatchID       string            `json:"batch_id"`
		Sequence      uint64            `json:"sequence"`
		SentAt        string            `json:"sent_at"`
		Records       []json.RawMessage `json:"records"`
	}{
		SchemaVersion: events.EventBatchV1Schema, SenderID: senderID,
		SenderEpoch: senderEpoch, BatchID: batchID, Sequence: sequence,
		SentAt:  sentAt.Round(0).UTC().Format(time.RFC3339Nano),
		Records: []json.RawMessage{recordJSON},
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return syntheticBatchMaterial{}, err
	}
	return syntheticBatchMaterial{senderEpoch: senderEpoch, batchID: batchID, digest: digest(raw), size: len(raw)}, nil
}

func importClaimArguments(dataset demohistory.Dataset, claims manifestClaims) []any {
	return []any{
		claims.importID, claims.manifestID, dataset.RawFileByteSHA256(),
		dataset.ManifestDatasetJCSDigest(), dataset.ImportedRowsJCSDigest(),
		int64(dataset.RecordCount()), dataset.SourceHealthJCSDigest(), claims.manifestDigest,
		claims.runScopeDigest, claims.publicKeyDigest, claims.signatureVerificationDigest,
		claims.clockAt, claims.issuedAt, claims.coverageStart, claims.coverageEnd,
	}
}

func readResult(ctx context.Context, tx pgx.Tx, importID string) (Result, error) {
	var result Result
	var recordCount int64
	var completedAt *time.Time
	err := tx.QueryRow(ctx, readImportSQL, importID).Scan(
		&result.importID, &result.manifestID, &result.datasetID,
		&result.rawFileByteSHA256, &result.manifestDatasetJCSDigest,
		&result.importedRowsJCSDigest, &recordCount,
		&result.sourceHealthJCSDigest, &result.manifestDigest,
		&result.runScopeDigest, &result.publicKeyDigest, &result.signatureVerificationDigest,
		&result.clockAt, &result.issuedAt, &result.coverageStart, &result.coverageEnd,
		&result.status, &result.failureCode, &result.attemptCount,
		&result.gatewayRecordCount, &result.authRecordCount,
		&result.sourceCoverageCount, &completedAt,
	)
	if err != nil {
		return Result{}, err
	}
	if recordCount < 0 {
		return Result{}, errors.New("invalid imported record count")
	}
	result.importedRecordCount = uint64(recordCount)
	if completedAt != nil {
		result.completedAt = completedAt.Round(0).UTC()
	}
	result.clockAt = result.clockAt.Round(0).UTC()
	result.issuedAt = result.issuedAt.Round(0).UTC()
	result.coverageStart = result.coverageStart.Round(0).UTC()
	result.coverageEnd = result.coverageEnd.Round(0).UTC()
	return result, nil
}

func readRecoveryResult(ctx context.Context, tx pgx.Tx, importID string) (Result, error) {
	var result Result
	var recordCount int64
	var completedAt *time.Time
	var schemaVersion, profile, datasetSchema, datasetLocator, pathCatalog string
	var rowsValid bool
	err := tx.QueryRow(ctx, readRecoveryImportSQL, importID).Scan(
		&result.importID, &result.manifestID, &schemaVersion, &profile,
		&result.datasetID, &datasetSchema, &datasetLocator, &pathCatalog,
		&result.rawFileByteSHA256, &result.manifestDatasetJCSDigest,
		&result.importedRowsJCSDigest, &recordCount,
		&result.sourceHealthJCSDigest, &result.manifestDigest,
		&result.runScopeDigest, &result.publicKeyDigest,
		&result.signatureVerificationDigest, &result.clockAt, &result.issuedAt,
		&result.coverageStart, &result.coverageEnd, &result.status,
		&result.failureCode, &result.attemptCount, &result.gatewayRecordCount,
		&result.authRecordCount, &result.sourceCoverageCount, &completedAt,
		&rowsValid, &result.recoveryGatewayRows, &result.recoveryAuthRows,
		&result.recoveryCoverageRows,
	)
	if err != nil {
		return Result{}, err
	}
	if schemaVersion != "demo-history-import-v1" || profile != validation.DemoHistoryProfile ||
		datasetSchema != validation.DemoHistoryDatasetSchemaVersion ||
		datasetLocator != validation.DemoHistoryDatasetLocator ||
		pathCatalog != "path-catalog-v1" || recordCount < 0 {
		return Result{}, reject(ErrorBinding)
	}
	result.recoveryRowsValid = rowsValid
	result.importedRecordCount = uint64(recordCount)
	if completedAt != nil {
		result.completedAt = completedAt.Round(0).UTC()
	}
	result.clockAt = result.clockAt.Round(0).UTC()
	result.issuedAt = result.issuedAt.Round(0).UTC()
	result.coverageStart = result.coverageStart.Round(0).UTC()
	result.coverageEnd = result.coverageEnd.Round(0).UTC()
	return result, nil
}

func verifyResultBinding(result Result, dataset demohistory.Dataset, claims manifestClaims) error {
	return verifyResultBindingMode(result, dataset, claims, true)
}

func verifyHistoricalResultBinding(result Result, dataset demohistory.Dataset, claims manifestClaims) error {
	return verifyResultBindingMode(result, dataset, claims, false)
}

func verifyRecoveryIdentity(result Result, dataset demohistory.Dataset, claims manifestClaims) error {
	if result.importID != claims.importID || result.manifestID != claims.manifestID ||
		result.datasetID != dataset.DatasetID() || result.rawFileByteSHA256 != dataset.RawFileByteSHA256() ||
		result.manifestDatasetJCSDigest != dataset.ManifestDatasetJCSDigest() ||
		result.importedRowsJCSDigest != dataset.ImportedRowsJCSDigest() ||
		result.importedRecordCount != dataset.RecordCount() ||
		result.sourceHealthJCSDigest != dataset.SourceHealthJCSDigest() ||
		result.manifestDigest != claims.manifestDigest || result.runScopeDigest != claims.runScopeDigest ||
		result.publicKeyDigest != claims.publicKeyDigest ||
		result.signatureVerificationDigest != claims.signatureVerificationDigest ||
		!result.clockAt.Equal(claims.clockAt) || !result.issuedAt.Equal(claims.issuedAt) ||
		!result.coverageStart.Equal(dataset.CoverageStart()) ||
		!result.coverageEnd.Equal(dataset.CoverageEnd()) {
		return reject(ErrorBinding)
	}
	return nil
}

func verifyResultBindingMode(
	result Result,
	dataset demohistory.Dataset,
	claims manifestClaims,
	requireFreshBinding bool,
) error {
	if result.importID != claims.importID || result.manifestID != claims.manifestID ||
		result.datasetID != dataset.DatasetID() || result.rawFileByteSHA256 != dataset.RawFileByteSHA256() ||
		result.manifestDatasetJCSDigest != dataset.ManifestDatasetJCSDigest() ||
		result.importedRowsJCSDigest != dataset.ImportedRowsJCSDigest() ||
		result.importedRecordCount != dataset.RecordCount() ||
		result.sourceHealthJCSDigest != dataset.SourceHealthJCSDigest() ||
		result.manifestDigest != claims.manifestDigest ||
		result.runScopeDigest != claims.runScopeDigest || result.publicKeyDigest != claims.publicKeyDigest ||
		result.signatureVerificationDigest != claims.signatureVerificationDigest ||
		!result.clockAt.Equal(claims.clockAt) || !result.issuedAt.Equal(claims.issuedAt) ||
		!result.coverageStart.Equal(dataset.CoverageStart()) || !result.coverageEnd.Equal(dataset.CoverageEnd()) ||
		result.status != "completed" || result.failureCode != "" ||
		result.gatewayRecordCount != 3 || result.authRecordCount != 1 || result.sourceCoverageCount != 2 ||
		result.completedAt.IsZero() ||
		(requireFreshBinding && result.verifiedBinding.HistoryCutoff().At().IsZero()) {
		return reject(ErrorBinding)
	}
	return nil
}

func (i *Importer) recordFailure(dataset demohistory.Dataset, claims manifestClaims, code ErrorCode) {
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	tx, err := i.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err = tx.Exec(ctx, lockImportSQL); err != nil {
		return
	}
	arguments := append(importClaimArguments(dataset, claims), string(code))
	if _, err = tx.Exec(ctx, recordFailureSQL, arguments...); err != nil {
		return
	}
	if err = tx.Commit(ctx); err == nil {
		committed = true
	}
}

func classify(ctx context.Context, err error) error { return reject(classifyCode(ctx, err)) }

func classifyCode(ctx context.Context, err error) ErrorCode {
	if contextError(ctx) != nil {
		return ErrorCanceled
	}
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503", "23505", "23514", "22023", "55000", "40001", "40P01":
			return ErrorConflict
		}
	}
	return ErrorStorage
}
