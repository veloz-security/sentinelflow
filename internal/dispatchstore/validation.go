package dispatchstore

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	actorPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	errorPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

func validJob(job jobSnapshot) bool {
	job = cloneJob(job)
	if !validUUID(job.jobID) || !validUUID(job.actionID) || !validUUID(job.policyID) ||
		job.policyVersion == 0 || job.policyVersion > 2_147_483_647 ||
		(job.state != "pending" && job.state != "retry" && job.state != "leased") || job.attempts < 0 ||
		job.maxAttempts < 1 || job.maxAttempts > 100 ||
		(!job.recoveryOnly && job.attempts >= job.maxAttempts) ||
		(job.recoveryOnly && job.attempts > job.maxAttempts) ||
		!validDatabaseTime(job.availableAt) || !validDatabaseTime(job.notBefore) ||
		!validDatabaseTime(job.validUntil) || !job.validUntil.After(job.notBefore) ||
		!actorPattern.MatchString(job.actorID) || !validIPv4(job.targetIPv4) ||
		len(job.artifact) < 1 || len(job.artifact) > capability.MaxArtifactBytes ||
		!validDigest(job.artifactDigest) || digestBytes(job.artifact) != job.artifactDigest {
		return false
	}
	for _, digest := range []string{
		job.evidenceSnapshotDigest, job.validationSnapshotDigest,
		job.authorizationDigest, job.reasonDigest, job.ownedSchemaDigest,
	} {
		if !validDigest(digest) {
			return false
		}
	}
	switch job.operation {
	case capability.OperationAdd:
		return job.kind == "dispatch_add" && job.originalAddDigest == nil
	case capability.OperationRevoke:
		return job.kind == "dispatch_revoke" && job.originalAddDigest != nil && validDigest(*job.originalAddDigest)
	case capability.OperationInspect:
		return job.kind == "dispatch_inspect" && job.originalAddDigest != nil && validDigest(*job.originalAddDigest)
	default:
		return false
	}
}

func validClaimRequest(request ClaimRequest) bool {
	return actorPattern.MatchString(request.LeaseOwner) && request.LeaseDuration >= time.Microsecond &&
		request.LeaseDuration <= MaxLeaseDuration && request.CandidateLimit >= 1 &&
		request.CandidateLimit <= MaxClaimCandidates &&
		request.LeaseDuration%time.Microsecond == 0 &&
		(request.LeaseToken == "" || uuidV4Pattern.MatchString(request.LeaseToken))
}

func validClaimedJob(claim ClaimedJob) bool {
	if !validJob(claim.job) || !uuidV4Pattern.MatchString(claim.leaseToken) ||
		!actorPattern.MatchString(claim.leaseOwner) || !validDatabaseTime(claim.claimedAt) ||
		!validDatabaseTime(claim.leaseUntil) || !claim.leaseUntil.After(claim.claimedAt) ||
		claim.leaseUntil.Sub(claim.claimedAt) > MaxLeaseDuration {
		return false
	}
	expected := digestClaim(claim)
	return subtle.ConstantTimeCompare(claim.claimDigest[:], expected[:]) == 1
}

func bindCapability(claim ClaimedJob, verified capability.VerifiedCapability, artifact []byte) bool {
	if !validClaimedJob(claim) || len(artifact) == 0 ||
		!bytes.Equal(artifact, claim.job.artifact) || verified.Digest() == "" {
		return false
	}
	value := verified.Value()
	original := ""
	if claim.job.originalAddDigest != nil {
		original = *claim.job.originalAddDigest
	}
	if value.SchemaVersion != capability.CapabilitySchemaVersion || value.JobID != claim.job.jobID ||
		value.Operation != claim.job.operation || value.ActionID != claim.job.actionID ||
		value.PolicyID != claim.job.policyID || value.PolicyVersion != claim.job.policyVersion ||
		value.TargetIPv4 != claim.job.targetIPv4 || value.ArtifactDigest != claim.job.artifactDigest ||
		value.OriginalAddDigest != original || value.EvidenceSnapshotDigest != claim.job.evidenceSnapshotDigest ||
		value.ValidationSnapshotDigest != claim.job.validationSnapshotDigest ||
		value.AuthorizationDigest != claim.job.authorizationDigest || value.ActorID != claim.job.actorID ||
		value.ReasonDigest != claim.job.reasonDigest || value.OwnedSchemaDigest != claim.job.ownedSchemaDigest {
		return false
	}
	return validMillisecondTime(value.IssuedAt) && validMillisecondTime(value.NotBefore) &&
		validMillisecondTime(value.ExpiresAt) && !value.IssuedAt.Before(ceilMillisecond(claim.claimedAt)) &&
		!value.NotBefore.Before(claim.job.notBefore) && !value.NotBefore.Before(value.IssuedAt) &&
		value.ExpiresAt.After(value.NotBefore) && !value.ExpiresAt.After(claim.job.validUntil) &&
		!value.ExpiresAt.After(claim.leaseUntil)
}

func validPersistedCapability(value PersistedCapability) bool {
	if value.recovered {
		return bindRecoveredCapability(value.claim, value.verified, value.claim.job.artifact)
	}
	return bindCapability(value.claim, value.verified, value.claim.job.artifact)
}

// A recovered capability retains its original signed time window. The current
// claim contributes only a new database lease fence; it must never rewrite or
// extend the original capability authority.
func bindRecoveredCapability(
	claim ClaimedJob,
	verified capability.VerifiedCapability,
	artifact []byte,
) bool {
	if !validClaimedJob(claim) || len(artifact) == 0 ||
		!bytes.Equal(artifact, claim.job.artifact) || verified.Digest() == "" {
		return false
	}
	value := verified.Value()
	original := ""
	if claim.job.originalAddDigest != nil {
		original = *claim.job.originalAddDigest
	}
	if value.SchemaVersion != capability.CapabilitySchemaVersion ||
		value.JobID != claim.job.jobID || value.Operation != claim.job.operation ||
		value.ActionID != claim.job.actionID || value.PolicyID != claim.job.policyID ||
		value.PolicyVersion != claim.job.policyVersion || value.TargetIPv4 != claim.job.targetIPv4 ||
		value.ArtifactDigest != claim.job.artifactDigest || value.OriginalAddDigest != original ||
		value.EvidenceSnapshotDigest != claim.job.evidenceSnapshotDigest ||
		value.ValidationSnapshotDigest != claim.job.validationSnapshotDigest ||
		value.AuthorizationDigest != claim.job.authorizationDigest || value.ActorID != claim.job.actorID ||
		value.ReasonDigest != claim.job.reasonDigest || value.OwnedSchemaDigest != claim.job.ownedSchemaDigest {
		return false
	}
	return validMillisecondTime(value.IssuedAt) && validMillisecondTime(value.NotBefore) &&
		validMillisecondTime(value.ExpiresAt) && !value.NotBefore.Before(value.IssuedAt) &&
		value.ExpiresAt.After(value.NotBefore) && value.ExpiresAt.Sub(value.IssuedAt) <= capability.MaxValidity &&
		!value.NotBefore.Before(claim.job.notBefore) && !value.ExpiresAt.After(claim.job.validUntil)
}

func validBoundResult(persisted PersistedCapability, value capability.ResultValue) bool {
	if !validPersistedCapability(persisted) || value.ElementHandle != nil ||
		!validMillisecondTime(value.StartedAt) || !validMillisecondTime(value.CompletedAt) {
		return false
	}
	capabilityValue := persisted.verified.Value()
	return value.CapabilityID == capabilityValue.CapabilityID &&
		value.CapabilityDigest == persisted.verified.Digest() && value.Operation == capabilityValue.Operation &&
		value.ActionID == capabilityValue.ActionID && value.ArtifactDigest == capabilityValue.ArtifactDigest &&
		value.TargetIPv4 == capabilityValue.TargetIPv4 && value.OwnedSchemaDigest == capabilityValue.OwnedSchemaDigest
}

func validFinishRequest(claim ClaimedJob, request FinishRequest) bool {
	if !validClaimedJob(claim) {
		return false
	}
	switch request.Outcome {
	case FinishCompleted:
		return request.RetryBackoff == 0 && request.ErrorCode == "" && request.ErrorDigest == "" &&
			request.Result != nil && validPersistedResult(*request.Result) && sameClaim(claim, request.Result.capability.claim)
	case FinishRetry:
		return request.Result == nil && request.RetryBackoff >= MinRetryBackoff &&
			request.RetryBackoff <= MaxRetryBackoff && request.RetryBackoff%time.Microsecond == 0 &&
			validFailure(request.ErrorCode, request.ErrorDigest) &&
			claim.job.attempts+1 < claim.job.maxAttempts
	case FinishDead:
		return request.Result == nil && request.RetryBackoff == 0 && validFailure(request.ErrorCode, request.ErrorDigest)
	default:
		return false
	}
}

func validPersistedResult(value PersistedResult) bool {
	return validPersistedCapability(value.capability) && validUUID(value.resultID) && validDigest(value.digest)
}

func validFailure(code, digest string) bool {
	return errorPattern.MatchString(code) && validDigest(digest)
}

func sameClaim(left, right ClaimedJob) bool {
	return subtle.ConstantTimeCompare(left.claimDigest[:], right.claimDigest[:]) == 1
}

func digestClaim(claim ClaimedJob) [32]byte {
	hash := sha256.New()
	for _, value := range []string{
		claim.job.jobID, claim.leaseToken, claim.leaseOwner,
		claim.claimedAt.UTC().Format(time.RFC3339Nano),
		claim.leaseUntil.UTC().Format(time.RFC3339Nano),
		claim.job.artifactDigest,
		fmt.Sprint(claim.job.recoveryOnly),
	} {
		_, _ = hash.Write([]byte{byte(len(value) >> 8), byte(len(value))})
		_, _ = hash.Write([]byte(value))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func nonceDigest(encoded string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		clear(raw)
		return "", false
	}
	digest := digestBytes(raw)
	clear(raw)
	return digest, true
}

func optionalString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func optionalEnum[T ~string](value *T) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func optionalUint(value *uint64) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func validUUID(value string) bool { return uuidPattern.MatchString(value) }

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == strings.TrimPrefix(value, "sha256:")
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func validDatabaseTime(value time.Time) bool {
	value = value.UTC()
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 &&
		value.Nanosecond()%int(time.Microsecond) == 0
}

func validMillisecondTime(value time.Time) bool {
	return validDatabaseTime(value) && value.Nanosecond()%int(time.Millisecond) == 0
}

func ceilMillisecond(value time.Time) time.Time {
	value = value.Round(0).UTC()
	floor := value.Truncate(time.Millisecond)
	if floor.Equal(value) {
		return floor
	}
	return floor.Add(time.Millisecond)
}

func floorMillisecond(value time.Time) time.Time {
	return value.Round(0).UTC().Truncate(time.Millisecond)
}
