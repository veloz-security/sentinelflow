package correlation

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

const initialIncidentVersion = 1

func NewIncident(group Group, at time.Time) (Incident, error) {
	if at.IsZero() {
		return Incident{}, correlationError(ErrorInvalidInput, "at")
	}
	at = canonicalTime(at)
	rebuilt, err := buildGroup(group.signals)
	if err != nil {
		return Incident{}, err
	}
	if at.Before(rebuilt.WindowEnd) {
		return Incident{}, correlationError(ErrorTimeRegression, "at")
	}
	return Incident{
		id:           incidentID(rebuilt.Snapshot.Digest()),
		version:      initialIncidentVersion,
		revision:     1,
		state:        IncidentOpen,
		createdAt:    at,
		updatedAt:    at,
		lastSignalAt: rebuilt.WindowEnd,
		snapshot:     rebuilt.Snapshot,
		signals:      rebuilt.Signals(),
		relations:    rebuilt.Relations(),
	}, nil
}

func (i Incident) BeginAnalysis(command Command) (Incident, TransitionResult, error) {
	fingerprint, duplicate, record, err := i.prepareCommand(command, "begin_analysis", "")
	if err != nil {
		return Incident{}, TransitionResult{}, err
	}
	if duplicate {
		return cloneIncident(i), duplicateTransition(i, record), nil
	}
	if i.state != IncidentOpen && i.state != IncidentAnalysisFailed {
		return Incident{}, TransitionResult{}, correlationError(ErrorInvalidTransition, "begin_analysis")
	}
	if i.state == IncidentAnalysisFailed && !i.CanRetryAnalysis() {
		return Incident{}, TransitionResult{}, correlationError(ErrorRetryNotAllowed, "analysis_failed")
	}
	if i.analysisAttempts >= MaximumAnalysisAttempts {
		return Incident{}, TransitionResult{}, correlationError(ErrorRetryNotAllowed, "analysis_attempts")
	}
	next := cloneIncident(i)
	next.state = IncidentAnalyzing
	next.failureReason = ""
	next.analysisAttempts++
	return next.commit(command, fingerprint), appliedTransition(next.revision + 1), nil
}

func (i Incident) CompleteAnalysis(command Command) (Incident, TransitionResult, error) {
	fingerprint, duplicate, record, err := i.prepareCommand(command, "complete_analysis", "")
	if err != nil {
		return Incident{}, TransitionResult{}, err
	}
	if duplicate {
		return cloneIncident(i), duplicateTransition(i, record), nil
	}
	if i.state != IncidentAnalyzing {
		return Incident{}, TransitionResult{}, correlationError(ErrorInvalidTransition, "complete_analysis")
	}
	next := cloneIncident(i)
	next.state = IncidentReviewReady
	next.failureReason = ""
	return next.commit(command, fingerprint), appliedTransition(next.revision + 1), nil
}

func (i Incident) FailAnalysis(command Command, reason AnalysisFailureReason) (Incident, TransitionResult, error) {
	if _, err := ClassifyAnalysisFailure(reason); err != nil {
		return Incident{}, TransitionResult{}, err
	}
	fingerprint, duplicate, record, err := i.prepareCommand(command, "fail_analysis", string(reason))
	if err != nil {
		return Incident{}, TransitionResult{}, err
	}
	if duplicate {
		return cloneIncident(i), duplicateTransition(i, record), nil
	}
	if i.state != IncidentAnalyzing {
		return Incident{}, TransitionResult{}, correlationError(ErrorInvalidTransition, "fail_analysis")
	}
	next := cloneIncident(i)
	next.state = IncidentAnalysisFailed
	next.failureReason = reason
	return next.commit(command, fingerprint), appliedTransition(next.revision + 1), nil
}

func (i Incident) CloseIdle(command Command) (Incident, TransitionResult, error) {
	fingerprint, duplicate, record, err := i.prepareCommand(command, "close_idle", "")
	if err != nil {
		return Incident{}, TransitionResult{}, err
	}
	if duplicate {
		return cloneIncident(i), duplicateTransition(i, record), nil
	}
	if i.state == IncidentClosed || i.state == IncidentAnalyzing {
		return Incident{}, TransitionResult{}, correlationError(ErrorInvalidTransition, "close_idle")
	}
	deadline := i.lastSignalAt.Add(IncidentIdleTimeout)
	if command.At.Before(deadline) {
		return Incident{}, TransitionResult{}, correlationError(ErrorIdleDeadlineNotReached, "at")
	}
	next := cloneIncident(i)
	next.state = IncidentClosed
	next.closedAt = canonicalTime(deadline)
	return next.commit(command, fingerprint), appliedTransition(next.revision + 1), nil
}

// RouteSignal either appends to this incident, reopens it, or deterministically
// creates a distinct incident. A different service never blocks same-source
// correlation, while a different source can never merge.
func (i Incident) RouteSignal(command Command, signal detection.Signal) (RouteResult, error) {
	values, err := normalizeSignals([]detection.Signal{signal})
	if err != nil {
		return RouteResult{}, err
	}
	signal = values[0]
	if command.At.IsZero() || command.At.Before(signal.WindowEnd) {
		return RouteResult{}, correlationError(ErrorTimeRegression, "at")
	}
	for _, existing := range i.signals {
		if existing.SignalID != signal.SignalID {
			continue
		}
		if !equalSignal(existing, signal) {
			return RouteResult{}, correlationError(ErrorConflictingSignal, signal.SignalID)
		}
		if err := i.validateDuplicateSignalCommand(command, signal); err != nil {
			return RouteResult{}, err
		}
		return RouteResult{Disposition: RouteDuplicateSignal, Current: cloneIncident(i)}, nil
	}

	fingerprint, duplicate, record, err := i.prepareCommand(command, "route_signal", signal.SignalID+"\n"+signal.Digest)
	if err != nil {
		return RouteResult{}, err
	}
	if duplicate {
		// A routed signal command can be replayed only after the signal has been
		// incorporated; the exact signal duplicate branch above normally handles
		// it. Retain this guard for aggregate history completeness.
		return RouteResult{Disposition: RouteDuplicateSignal, Current: cloneIncident(i)}, nil
	}
	_ = record

	if signal.SourceIP != i.snapshot.SourceIP() {
		return i.routeToNewIncident(command, signal)
	}
	if i.state == IncidentClosed {
		if command.At.Before(i.closedAt) {
			return RouteResult{}, correlationError(ErrorTimeRegression, "at")
		}
		if !command.At.After(i.closedAt.Add(IncidentReopenWindow)) {
			return i.appendSignal(command, fingerprint, signal, true)
		}
		return i.routeToNewIncident(command, signal)
	}

	related := false
	for _, existing := range i.signals {
		if _, direct := temporalRelation(existing, signal); direct {
			related = true
			break
		}
	}
	if !related {
		return i.routeToNewIncident(command, signal)
	}
	return i.appendSignal(command, fingerprint, signal, false)
}

func (i Incident) validateDuplicateSignalCommand(command Command, signal detection.Signal) error {
	if !digestPattern.MatchString(command.ID) {
		return correlationError(ErrorInvalidInput, "command.id")
	}
	if command.At.IsZero() {
		return correlationError(ErrorInvalidInput, "command.at")
	}
	command.At = canonicalTime(command.At)
	fingerprint := commandFingerprint("route_signal", command, signal.SignalID+"\n"+signal.Digest)
	for _, record := range i.commands {
		if record.id != command.ID {
			continue
		}
		if record.fingerprint != fingerprint {
			return correlationError(ErrorIdempotencyConflict, "command.id")
		}
		return nil
	}
	// Event identity is independently idempotent. A new command ID may replay an
	// exact retained signal without changing state or requiring the old revision.
	return nil
}

func (i Incident) appendSignal(command Command, fingerprint string, signal detection.Signal, reopening bool) (RouteResult, error) {
	next := cloneIncident(i)
	previousSignals := cloneSignals(next.signals)
	next.signals = append(next.signals, cloneSignal(signal))
	sortSignals(next.signals)
	snapshot, err := buildEvidenceSnapshot(next.signals)
	if err != nil {
		return RouteResult{}, err
	}
	next.snapshot = snapshot
	next.lastSignalAt = snapshot.WindowEnd()
	next.state = IncidentOpen
	next.failureReason = ""
	next.closedAt = time.Time{}
	next.relations = buildRelations(next.signals)
	disposition := RouteAppended
	if reopening {
		disposition = RouteReopened
		anchor := latestSignal(previousSignals)
		next.relations = replacePairRelation(next.relations, makeRelation(anchor, signal, TemporalReopenedWithinThirtyMinutes))
	}
	next = next.commit(command, fingerprint)
	return RouteResult{Disposition: disposition, Current: next}, nil
}

func (i Incident) routeToNewIncident(command Command, signal detection.Signal) (RouteResult, error) {
	group, err := buildGroup([]detection.Signal{signal})
	if err != nil {
		return RouteResult{}, err
	}
	created, err := NewIncident(group, command.At)
	if err != nil {
		return RouteResult{}, err
	}
	return RouteResult{
		Disposition: RouteNewIncident,
		Current:     cloneIncident(i),
		NewIncident: &created,
	}, nil
}

func (i Incident) prepareCommand(command Command, kind, payload string) (string, bool, commandRecord, error) {
	if !digestPattern.MatchString(command.ID) {
		return "", false, commandRecord{}, correlationError(ErrorInvalidInput, "command.id")
	}
	if command.At.IsZero() {
		return "", false, commandRecord{}, correlationError(ErrorInvalidInput, "command.at")
	}
	command.At = canonicalTime(command.At)
	fingerprint := commandFingerprint(kind, command, payload)
	for _, record := range i.commands {
		if record.id != command.ID {
			continue
		}
		if record.fingerprint != fingerprint {
			return "", false, commandRecord{}, correlationError(ErrorIdempotencyConflict, "command.id")
		}
		return fingerprint, true, record, nil
	}
	if command.ExpectedRevision != i.revision {
		return "", false, commandRecord{}, correlationError(ErrorStaleRevision, "command.expected_revision")
	}
	if command.At.Before(i.updatedAt) {
		return "", false, commandRecord{}, correlationError(ErrorTimeRegression, "command.at")
	}
	return fingerprint, false, commandRecord{}, nil
}

func (i Incident) commit(command Command, fingerprint string) Incident {
	next := cloneIncident(i)
	// Version is the immutable evidence/state contract consumed by downstream
	// analysis and HIL. Every effective aggregate mutation advances it exactly
	// once; idempotent command and signal replays return before commit and
	// therefore cannot manufacture a new incident version.
	next.version++
	next.revision++
	next.updatedAt = canonicalTime(command.At)
	next.commands = append(next.commands, commandRecord{
		id:              command.ID,
		fingerprint:     fingerprint,
		appliedRevision: next.revision,
	})
	return next
}

func commandFingerprint(kind string, command Command, payload string) string {
	var builder strings.Builder
	writeFingerprintLine(&builder, "incident-command-v1")
	writeFingerprintLine(&builder, kind)
	writeFingerprintLine(&builder, command.ID)
	writeFingerprintLine(&builder, strconv.FormatUint(command.ExpectedRevision, 10))
	writeFingerprintLine(&builder, formatTime(command.At))
	writeFingerprintLine(&builder, payload)
	return sha256Digest([]byte(builder.String()))
}

func writeFingerprintLine(builder *strings.Builder, value string) {
	builder.WriteString(strconv.Itoa(len(value)))
	builder.WriteByte(':')
	builder.WriteString(value)
	builder.WriteByte('\n')
}

func incidentID(snapshotDigest string) string {
	sum := sha256.Sum256([]byte("sentinelflow-incident-id-v1\n" + snapshotDigest))
	bytes := [16]byte{}
	copy(bytes[:], sum[:16])
	bytes[6] = (bytes[6] & 0x0f) | 0x80
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

func latestSignal(signals []detection.Signal) detection.Signal {
	latest := signals[0]
	for _, signal := range signals[1:] {
		if signal.WindowEnd.After(latest.WindowEnd) ||
			(signal.WindowEnd.Equal(latest.WindowEnd) && signal.SignalID > latest.SignalID) {
			latest = signal
		}
	}
	return latest
}

func replacePairRelation(relations []Relation, replacement Relation) []Relation {
	result := make([]Relation, 0, len(relations)+1)
	for _, relation := range relations {
		if relation.LeftSignalID == replacement.LeftSignalID && relation.RightSignalID == replacement.RightSignalID {
			continue
		}
		result = append(result, relation)
	}
	result = append(result, replacement)
	sortRelations(result)
	return result
}

func appliedTransition(revision uint64) TransitionResult {
	return TransitionResult{
		Disposition:     TransitionApplied,
		AppliedRevision: revision,
		CurrentRevision: revision,
	}
}

func duplicateTransition(incident Incident, record commandRecord) TransitionResult {
	return TransitionResult{
		Disposition:     TransitionIdempotentDuplicate,
		AppliedRevision: record.appliedRevision,
		CurrentRevision: incident.revision,
	}
}
