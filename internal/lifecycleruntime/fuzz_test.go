package lifecycleruntime

import (
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

func FuzzValidateClaimProjection(f *testing.F) {
	seed := validClaimInput()
	f.Add(seed.ScheduleIdentity, seed.LeaseIdentity, seed.AuthorizationID, seed.ActionID, seed.PolicyID,
		seed.TargetIPv4, string(seed.Purpose), int64(time.Minute))
	f.Add("bad schedule", "", "bad", "bad", "bad", "203.0.113.020", "add", int64(-1))
	f.Fuzz(func(t *testing.T, schedule, lease, authorization, action, policy, target, purpose string, validityNanos int64) {
		input := validClaimInput()
		input.ScheduleIdentity = schedule
		input.LeaseIdentity = lease
		input.AuthorizationID = authorization
		input.ActionID = action
		input.PolicyID = policy
		input.TargetIPv4 = target
		input.Purpose = lifecycleartifact.Purpose(purpose)
		validityNanos %= int64(10 * time.Minute)
		input.ValidUntil = input.RequestedAt.Add(time.Duration(validityNanos))
		claim := NewClaim(input)
		if validClaim(claim) {
			if !opaqueIdentityPattern.MatchString(schedule) || !opaqueIdentityPattern.MatchString(lease) ||
				!uuidPattern.MatchString(authorization) || !uuidPattern.MatchString(action) ||
				!uuidPattern.MatchString(policy) ||
				!validIPv4(target) || !validPurpose(lifecycleartifact.Purpose(purpose)) {
				t.Fatal("invalid projection accepted")
			}
		}
	})
}
