package policy

import "math"

type PolicyState string

const (
	PolicyStateDraft         PolicyState = "draft"
	PolicyStateValidating    PolicyState = "validating"
	PolicyStateValid         PolicyState = "valid"
	PolicyStateInvalid       PolicyState = "invalid"
	PolicyStateStale         PolicyState = "stale"
	PolicyStateApproved      PolicyState = "approved"
	PolicyStateRejected      PolicyState = "rejected"
	PolicyStateQueued        PolicyState = "queued"
	PolicyStateActive        PolicyState = "active"
	PolicyStateExpired       PolicyState = "expired"
	PolicyStateFailed        PolicyState = "failed"
	PolicyStateRevoked       PolicyState = "revoked"
	PolicyStateIndeterminate PolicyState = "indeterminate"
)

var allowedPolicyTransitions = map[PolicyState]map[PolicyState]struct{}{
	PolicyStateDraft: {
		PolicyStateValidating: {},
		PolicyStateStale:      {},
	},
	PolicyStateValidating: {
		PolicyStateValid:   {},
		PolicyStateInvalid: {},
		PolicyStateStale:   {},
	},
	PolicyStateValid: {
		PolicyStateApproved: {},
		PolicyStateRejected: {},
		PolicyStateStale:    {},
	},
	PolicyStateApproved: {
		PolicyStateQueued: {},
		PolicyStateStale:  {},
	},
	PolicyStateQueued: {
		PolicyStateActive:        {},
		PolicyStateFailed:        {},
		PolicyStateIndeterminate: {},
		PolicyStateStale:         {},
	},
	PolicyStateActive: {
		PolicyStateExpired:       {},
		PolicyStateFailed:        {},
		PolicyStateRevoked:       {},
		PolicyStateIndeterminate: {},
	},
	PolicyStateIndeterminate: {
		PolicyStateActive:  {},
		PolicyStateExpired: {},
		PolicyStateFailed:  {},
		PolicyStateRevoked: {},
	},
}

var allPolicyStates = map[PolicyState]struct{}{
	PolicyStateDraft:         {},
	PolicyStateValidating:    {},
	PolicyStateValid:         {},
	PolicyStateInvalid:       {},
	PolicyStateStale:         {},
	PolicyStateApproved:      {},
	PolicyStateRejected:      {},
	PolicyStateQueued:        {},
	PolicyStateActive:        {},
	PolicyStateExpired:       {},
	PolicyStateFailed:        {},
	PolicyStateRevoked:       {},
	PolicyStateIndeterminate: {},
}

// PolicyLifecycle is an immutable optimistic-concurrency value. Revision is a
// state-row revision and is deliberately distinct from the policy artifact's
// immutable PolicyVersion.
type PolicyLifecycle struct {
	policyID      string
	policyVersion uint32
	state         PolicyState
	revision      uint64
}

func NewPolicyLifecycle(policy CheckedResponsePolicy) (PolicyLifecycle, error) {
	value := policy.value
	if len(policy.canonical) == 0 || policy.digest == "" || !evidenceIDPattern.MatchString(value.PolicyID) || value.PolicyVersion == 0 {
		return PolicyLifecycle{}, rejectPolicy(PolicyErrorState)
	}
	return PolicyLifecycle{
		policyID:      value.PolicyID,
		policyVersion: value.PolicyVersion,
		state:         PolicyStateDraft,
		revision:      1,
	}, nil
}

func RestorePolicyLifecycle(policyID string, policyVersion uint32, state PolicyState, revision uint64) (PolicyLifecycle, error) {
	if !evidenceIDPattern.MatchString(policyID) || policyVersion == 0 || policyVersion > math.MaxInt32 || revision == 0 || !validPolicyState(state) {
		return PolicyLifecycle{}, rejectPolicy(PolicyErrorState)
	}
	return PolicyLifecycle{policyID: policyID, policyVersion: policyVersion, state: state, revision: revision}, nil
}

func (l PolicyLifecycle) PolicyID() string      { return l.policyID }
func (l PolicyLifecycle) PolicyVersion() uint32 { return l.policyVersion }
func (l PolicyLifecycle) State() PolicyState    { return l.state }
func (l PolicyLifecycle) StateRevision() uint64 { return l.revision }

// Transition performs a compare-and-swap transition. Repeating the already
// committed state with the current revision is idempotent and does not advance
// the revision. Every other accepted transition advances exactly once.
func (l PolicyLifecycle) Transition(expectedRevision uint64, next PolicyState) (PolicyLifecycle, error) {
	if expectedRevision == 0 || expectedRevision != l.revision {
		return PolicyLifecycle{}, rejectPolicy(PolicyErrorStateRevision)
	}
	if !validPolicyState(l.state) || !validPolicyState(next) {
		return PolicyLifecycle{}, rejectPolicy(PolicyErrorState)
	}
	if next == l.state {
		return l, nil
	}
	if !CanTransitionPolicy(l.state, next) || l.revision == math.MaxUint64 {
		return PolicyLifecycle{}, rejectPolicy(PolicyErrorTransition)
	}
	l.state = next
	l.revision++
	return l, nil
}

func CanTransitionPolicy(current, next PolicyState) bool {
	nextStates, ok := allowedPolicyTransitions[current]
	if !ok {
		return false
	}
	_, ok = nextStates[next]
	return ok
}

func validPolicyState(state PolicyState) bool {
	_, ok := allPolicyStates[state]
	return ok
}
