package lifecycleruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

const (
	idempotencyDigestDomain = "sentinelflow inspection-schedule-idempotency-v1\n"
	failureDigestDomain     = "sentinelflow lifecycle-runtime-failure-v1\n"
)

var (
	opaqueIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	uuidPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	schedulerPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func idempotencyDigest(claim Claim) string {
	// Lease identity is deliberately excluded: a reclaimed immutable schedule
	// must retain the same idempotency key across process and lease boundaries.
	return digest(idempotencyDigestDomain + claim.scheduleIdentity + "\n")
}

func checkedFailure(code FailureCode) Failure {
	return Failure{code: code, digest: digest(failureDigestDomain + string(code) + "\n")}
}

func validClaim(claim Claim) bool {
	if !opaqueIdentityPattern.MatchString(claim.scheduleIdentity) ||
		!opaqueIdentityPattern.MatchString(claim.leaseIdentity) ||
		!uuidPattern.MatchString(claim.authorizationID) ||
		!uuidPattern.MatchString(claim.actionID) || !uuidPattern.MatchString(claim.policyID) ||
		claim.actionVersion == 0 || claim.actionVersion > 1<<31-1 ||
		claim.policyVersion == 0 || claim.policyVersion > 1<<31-1 ||
		!validIPv4(claim.targetIPv4) || !validPurpose(claim.purpose) {
		return false
	}
	for _, value := range []string{
		claim.originalAddDigest, claim.originalAuthorizationDigest,
		claim.evidenceSnapshotDigest, claim.validationSnapshotDigest,
		claim.ownedSchemaDigest,
	} {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	requestedAt, requestedOK := normalizedTime(claim.requestedAt)
	validUntil, validOK := normalizedTime(claim.validUntil)
	return requestedOK && validOK && validUntil.After(requestedAt) &&
		!validUntil.After(requestedAt.Add(lifecycleartifact.MaxAuthorizationValidity))
}

func validIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func validPurpose(value lifecycleartifact.Purpose) bool {
	return value == lifecycleartifact.PurposeReconciliation ||
		value == lifecycleartifact.PurposeExpiryConfirmation ||
		value == lifecycleartifact.PurposeOperatorStatus
}

func normalizedTime(value time.Time) (time.Time, bool) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, false
	}
	value = value.Round(0).UTC()
	return value, value.Year() >= 1 && value.Year() <= 9999
}

func validConfig(config Config) bool {
	return schedulerPattern.MatchString(config.SchedulerID) &&
		config.PollInterval > 0 && config.PollInterval <= MaxPollInterval &&
		config.CleanupTimeout > 0 && config.CleanupTimeout <= MaxCleanupTimeout
}
