package nftrunner

import (
	"context"

	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
)

type processKind uint8

const (
	processMutation processKind = iota + 1
	processInspect
)

var (
	mutationArguments = [...]string{"-f", "-"}
	inspectArguments  = [...]string{"--json", "list", "set", "inet", "sentinelflow", "blacklist_ipv4"}
)

type processRequest struct {
	kind  processKind
	stdin []byte
}

func (r processRequest) path() string { return executor.FixedNFTBinaryPath }

func (r processRequest) arguments() []string {
	switch r.kind {
	case processMutation:
		return append([]string(nil), mutationArguments[:]...)
	case processInspect:
		return append([]string(nil), inspectArguments[:]...)
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

// processFunc is deliberately unexported. Production constructors install the
// fixed OS implementation; only package tests replace it.
type processFunc func(context.Context, processRequest) (processResult, bool)
