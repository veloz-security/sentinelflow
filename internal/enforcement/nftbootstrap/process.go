package nftbootstrap

import "context"

type processKind uint8

const (
	processInventory processKind = iota + 1
	processApply
	processVerifyLive
)

var (
	// Stateless snapshots retain foreign ruleset structure while removing
	// mutable packet/byte counter values. Bootstrap compares the foreign
	// projection before and after applying the strictly owned base contract.
	inventoryArguments = [...]string{"--json", "--stateless", "list", "ruleset"}
	applyArguments     = [...]string{"-f", "-"}
	// Steady-state verification is deliberately scoped to the owned table, so
	// unrelated namespace growth cannot consume the executor's read-back bound
	// or disable otherwise valid enforcement.
	verifyArguments = [...]string{"--json", "--stateless", "list", "table", "inet", "sentinelflow"}
)

type processRequest struct {
	kind  processKind
	stdin []byte
}

func (request processRequest) path() string { return FixedNFTBinaryPath }

func (request processRequest) arguments() []string {
	switch request.kind {
	case processInventory:
		return append([]string(nil), inventoryArguments[:]...)
	case processApply:
		return append([]string(nil), applyArguments[:]...)
	case processVerifyLive:
		return append([]string(nil), verifyArguments[:]...)
	default:
		return nil
	}
}

type processResult struct {
	exitStatus int
	stdout     []byte
	stderr     []byte
	overflow   bool
	signaled   bool
}

// processFunc remains unexported so production callers cannot substitute an
// executable, argv, environment, or command surface. Package tests use it to
// exercise failure behavior without nft privileges.
type processFunc func(context.Context, processRequest) (processResult, bool)
