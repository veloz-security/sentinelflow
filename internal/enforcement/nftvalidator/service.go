// Package nftvalidator isolates the privileged nftables syntax-check process
// behind a strict, one-operation Unix-domain-socket protocol. It has no
// database, OpenAI, administrator, dispatcher, executor, or mutation API.
package nftvalidator

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

const (
	replayTTL        = 5 * time.Minute
	maxReplayEntries = 4096
)

type SyntaxChecker interface {
	Check(context.Context, nftcheck.Input) (nftcheck.Evidence, error)
}

type ServiceConfig struct {
	Checker         SyntaxChecker
	BaseContract    []byte
	NFTBinaryDigest string
	NFTVersion      string
	Now             func() time.Time
}

// Service is immutable except for its bounded nonce replay cache.
type Service struct {
	checker         SyntaxChecker
	baseContract    []byte
	nftBinaryDigest string
	nftVersion      string
	now             func() time.Time
	replayMu        sync.Mutex
	replay          map[string]time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Checker == nil || !digestPattern.MatchString(config.NFTBinaryDigest) ||
		!validNFTVersion(config.NFTVersion) || len(config.BaseContract) == 0 ||
		len(config.BaseContract) > nftcheck.MaxBaseContractBytes ||
		digestBytes(config.BaseContract) != nftcheck.PinnedBaseContractDigest {
		return nil, reject(ErrorInvalidConfiguration)
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		checker: config.Checker, baseContract: append([]byte(nil), config.BaseContract...),
		nftBinaryDigest: config.NFTBinaryDigest, nftVersion: config.NFTVersion,
		now: config.Now, replay: make(map[string]time.Time),
	}, nil
}

// Handle accepts only a canonical nft-validator-request-v1 and returns only a
// canonical nft-validator-response-v1. It never returns raw process output.
func (s *Service) Handle(ctx context.Context, payload []byte) ([]byte, error) {
	if s == nil || s.checker == nil || ctx == nil {
		return nil, reject(ErrorInvalidConfiguration)
	}
	requestValue, err := decodeRequest(payload)
	if err != nil {
		return nil, reject(ErrorRequestInvalid)
	}
	digest := requestDigest(payload)
	if code := s.claimNonce(requestValue.nonce); code != "" {
		return encodeResponse(response{
			baseContractDigest: nftcheck.PinnedBaseContractDigest,
			errorCode:          string(code),
			evidence:           initialEvidence(requestValue.candidateDigest),
			nftBinaryDigest:    s.nftBinaryDigest,
			nftBinaryPath:      nftcheck.FixedNFTBinaryPath,
			nftVersion:         s.nftVersion,
			passed:             false,
			requestDigest:      digest,
		})
	}

	evidence, checkErr := s.checker.Check(ctx, nftcheck.Input{
		CanonicalBytes:     append([]byte(nil), requestValue.candidate...),
		CanonicalDigest:    requestValue.candidateDigest,
		BaseContract:       append([]byte(nil), s.baseContract...),
		BaseContractDigest: nftcheck.PinnedBaseContractDigest,
	})
	remoteCode := ""
	passed := checkErr == nil
	if evidence.CanonicalDigest == "" {
		evidence.CanonicalDigest = requestValue.candidateDigest
	}
	if evidence.BaseContractDigest == "" {
		evidence.BaseContractDigest = nftcheck.PinnedBaseContractDigest
	}
	if evidence.CanonicalDigest != requestValue.candidateDigest ||
		evidence.BaseContractDigest != nftcheck.PinnedBaseContractDigest {
		evidence = initialEvidence(requestValue.candidateDigest)
		checkErr = &nftcheck.Error{Code: nftcheck.ErrorRunnerUnavailable}
		passed = false
	}
	if !validEvidence(evidence) {
		evidence = initialEvidence(requestValue.candidateDigest)
		checkErr = &nftcheck.Error{Code: nftcheck.ErrorRunnerUnavailable}
		passed = false
	}
	if checkErr != nil {
		var typed *nftcheck.Error
		if !errors.As(checkErr, &typed) || typed == nil || !validRemoteErrorCode(string(typed.Code)) {
			remoteCode = string(nftcheck.ErrorRunnerUnavailable)
		} else {
			remoteCode = string(typed.Code)
		}
	}
	return encodeResponse(response{
		baseContractDigest: nftcheck.PinnedBaseContractDigest,
		errorCode:          remoteCode,
		evidence:           evidence,
		nftBinaryDigest:    s.nftBinaryDigest,
		nftBinaryPath:      nftcheck.FixedNFTBinaryPath,
		nftVersion:         s.nftVersion,
		passed:             passed,
		requestDigest:      digest,
	})
}

func (s *Service) claimNonce(nonce string) ErrorCode {
	now := s.now().UTC()
	if now.IsZero() {
		return ErrorReplayCacheFull
	}
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for key, expiresAt := range s.replay {
		if !expiresAt.After(now) {
			delete(s.replay, key)
		}
	}
	if _, exists := s.replay[nonce]; exists {
		return ErrorRequestReplayed
	}
	if len(s.replay) >= maxReplayEntries {
		return ErrorReplayCacheFull
	}
	s.replay[nonce] = now.Add(replayTTL)
	return ""
}

func (*Service) String() string     { return "nftvalidator.Service{artifacts:[REDACTED]}" }
func (s *Service) GoString() string { return s.String() }
