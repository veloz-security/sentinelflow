package nftvalidator

import (
	"bytes"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

func combineCheckScript(baseContract, candidate []byte) ([]byte, error) {
	if len(baseContract) == 0 || len(baseContract) > nftcheck.MaxBaseContractBytes ||
		digestBytes(baseContract) != nftcheck.PinnedBaseContractDigest ||
		baseContract[len(baseContract)-1] != '\n' || bytes.Contains(baseContract, []byte{'\r'}) ||
		!validCandidateEnvelope(candidate) {
		return nil, reject(ErrorInvalidConfiguration)
	}
	// The pinned table/set/chain declaration and the candidate are checked as
	// one parser transaction. --check performs no mutation, so an initially
	// empty validator namespace remains empty after both pass and rejection.
	value := make([]byte, 0, len(baseContract)+len(candidate))
	value = append(value, baseContract...)
	value = append(value, candidate...)
	if len(value) > nftcheck.MaxBaseContractBytes+nftcheck.MaxCandidateBytes {
		return nil, reject(ErrorRequestInvalid)
	}
	return value, nil
}

func runnerError(code nftcheck.ErrorCode) error { return &nftcheck.Error{Code: code} }
