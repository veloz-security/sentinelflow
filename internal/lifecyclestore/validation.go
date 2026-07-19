package lifecyclestore

import (
	"net/netip"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
	"github.com/devwooops/sentinelflow/internal/lifecycleruntime"
)

var (
	identityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type claimProjection struct {
	scheduleIdentity            string
	leaseIdentity               string
	authorizationID             string
	actionID                    string
	actionVersion               int32
	policyID                    string
	policyVersion               int32
	targetIPv4                  string
	originalAddDigest           string
	originalAuthorizationDigest string
	evidenceSnapshotDigest      string
	validationSnapshotDigest    string
	ownedSchemaDigest           string
	purpose                     string
	requestedAt                 time.Time
	validUntil                  time.Time
}

func validConfig(config Config) bool {
	return identityPattern.MatchString(config.SchedulerID) &&
		identityPattern.MatchString(config.LeaseOwner) &&
		config.LeaseDuration >= time.Second && config.LeaseDuration <= MaxLeaseDuration &&
		config.LeaseDuration%time.Second == 0 &&
		config.RetryBackoff >= time.Second && config.RetryBackoff <= MaxRetryBackoff &&
		config.RetryBackoff%time.Second == 0
}

func validProjection(value claimProjection) bool {
	if !uuidPattern.MatchString(value.scheduleIdentity) ||
		!uuidPattern.MatchString(value.leaseIdentity) ||
		!uuidPattern.MatchString(value.authorizationID) ||
		!uuidPattern.MatchString(value.actionID) || !uuidPattern.MatchString(value.policyID) ||
		value.actionVersion < 1 || value.policyVersion < 1 ||
		!validIPv4(value.targetIPv4) || !validPurpose(value.purpose) {
		return false
	}
	for _, digest := range []string{
		value.originalAddDigest, value.originalAuthorizationDigest,
		value.evidenceSnapshotDigest, value.validationSnapshotDigest,
		value.ownedSchemaDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return false
		}
	}
	requestedAt, requestedOK := normalizedTime(value.requestedAt)
	validUntil, validOK := normalizedTime(value.validUntil)
	return requestedOK && validOK && validUntil.After(requestedAt) &&
		!validUntil.After(requestedAt.Add(lifecycleartifact.MaxAuthorizationValidity))
}

func (value claimProjection) claim() lifecycleruntime.Claim {
	return lifecycleruntime.NewClaim(lifecycleruntime.ClaimInput{
		ScheduleIdentity: value.scheduleIdentity, LeaseIdentity: value.leaseIdentity,
		AuthorizationID: value.authorizationID, ActionID: value.actionID,
		ActionVersion: uint32(value.actionVersion), PolicyID: value.policyID,
		PolicyVersion: uint32(value.policyVersion), TargetIPv4: value.targetIPv4,
		OriginalAddDigest:           value.originalAddDigest,
		OriginalAuthorizationDigest: value.originalAuthorizationDigest,
		EvidenceSnapshotDigest:      value.evidenceSnapshotDigest,
		ValidationSnapshotDigest:    value.validationSnapshotDigest,
		OwnedSchemaDigest:           value.ownedSchemaDigest,
		Purpose:                     lifecycleartifact.Purpose(value.purpose),
		RequestedAt:                 value.requestedAt.Round(0).UTC(),
		ValidUntil:                  value.validUntil.Round(0).UTC(),
	})
}

func validIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func validPurpose(value string) bool {
	return value == string(lifecycleartifact.PurposeReconciliation) ||
		value == string(lifecycleartifact.PurposeExpiryConfirmation) ||
		value == string(lifecycleartifact.PurposeOperatorStatus)
}

func normalizedTime(value time.Time) (time.Time, bool) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, false
	}
	value = value.Round(0).UTC()
	return value, value.Year() >= 1 && value.Year() <= 9999
}

func validStoreIdentity(claim lifecycleruntime.Claim) (string, string, bool) {
	schedule, lease := claim.StoreIdentity()
	return schedule, lease,
		uuidPattern.MatchString(schedule) && uuidPattern.MatchString(lease) &&
			claim.ActionVersion() >= 1 && claim.ActionVersion() <= 2_147_483_647
}
