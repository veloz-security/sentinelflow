package nftvalidator

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

const (
	RequestSchemaVersion  = "nft-validator-request-v1"
	ResponseSchemaVersion = "nft-validator-response-v1"
	requestDigestDomain   = "sentinelflow nft-validator-request-v1\x00"
	nonceBytes            = 16
)

var (
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^nftables v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
)

type requestWire struct {
	CandidateB64URL string `json:"candidate_b64url"`
	CandidateDigest string `json:"candidate_digest"`
	NonceB64URL     string `json:"nonce_b64url"`
	SchemaVersion   string `json:"schema_version"`
}

type request struct {
	candidate       []byte
	candidateDigest string
	nonce           string
}

// Fields remain in lexical order so json.Marshal emits the frozen canonical
// wire representation without depending on maps.
type evidenceWire struct {
	BaseContractDigest     string    `json:"base_contract_digest"`
	CanonicalDigest        string    `json:"canonical_digest"`
	GateVersion            string    `json:"gate_version"`
	NFTBinaryPath          string    `json:"nft_binary_path"`
	NFTVersion             string    `json:"nft_version"`
	SyntaxArguments        [3]string `json:"syntax_arguments"`
	SyntaxExitStatus       int       `json:"syntax_exit_status"`
	SyntaxOutputByteCount  uint32    `json:"syntax_output_byte_count"`
	SyntaxOutputDigest     string    `json:"syntax_output_digest"`
	VersionArguments       [1]string `json:"version_arguments"`
	VersionExitStatus      int       `json:"version_exit_status"`
	VersionOutputByteCount uint32    `json:"version_output_byte_count"`
	VersionOutputDigest    string    `json:"version_output_digest"`
}

type responseWire struct {
	BaseContractDigest string       `json:"base_contract_digest"`
	ErrorCode          string       `json:"error_code"`
	Evidence           evidenceWire `json:"evidence"`
	NFTBinaryDigest    string       `json:"nft_binary_digest"`
	NFTBinaryPath      string       `json:"nft_binary_path"`
	NFTVersion         string       `json:"nft_version"`
	Passed             bool         `json:"passed"`
	RequestDigest      string       `json:"request_digest"`
	SchemaVersion      string       `json:"schema_version"`
}

type response struct {
	baseContractDigest string
	errorCode          string
	evidence           nftcheck.Evidence
	nftBinaryDigest    string
	nftBinaryPath      string
	nftVersion         string
	passed             bool
	requestDigest      string
}

func encodeRequest(candidate []byte, candidateDigest string, nonce []byte) ([]byte, error) {
	if !validCandidateEnvelope(candidate) || digestBytes(candidate) != candidateDigest || len(nonce) != nonceBytes {
		return nil, reject(ErrorRequestInvalid)
	}
	wire := requestWire{
		CandidateB64URL: base64.RawURLEncoding.EncodeToString(candidate),
		CandidateDigest: candidateDigest,
		NonceB64URL:     base64.RawURLEncoding.EncodeToString(nonce),
		SchemaVersion:   RequestSchemaVersion,
	}
	return marshalBounded(wire)
}

func decodeRequest(payload []byte) (request, error) {
	if !validJSONPayload(payload) {
		return request{}, reject(ErrorRequestInvalid)
	}
	var wire requestWire
	if err := decodeExact(payload, &wire); err != nil || wire.SchemaVersion != RequestSchemaVersion ||
		!digestPattern.MatchString(wire.CandidateDigest) || len(wire.NonceB64URL) != 22 {
		return request{}, reject(ErrorRequestInvalid)
	}
	candidate, err := base64.RawURLEncoding.Strict().DecodeString(wire.CandidateB64URL)
	if err != nil || !validCandidateEnvelope(candidate) || digestBytes(candidate) != wire.CandidateDigest {
		return request{}, reject(ErrorRequestInvalid)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(wire.NonceB64URL)
	if err != nil || len(nonce) != nonceBytes || base64.RawURLEncoding.EncodeToString(nonce) != wire.NonceB64URL {
		return request{}, reject(ErrorRequestInvalid)
	}
	return request{
		candidate: append([]byte(nil), candidate...), candidateDigest: wire.CandidateDigest, nonce: wire.NonceB64URL,
	}, nil
}

func encodeResponse(value response) ([]byte, error) {
	if !validResponse(value) {
		return nil, reject(ErrorResponseInvalid)
	}
	wire := responseWire{
		BaseContractDigest: value.baseContractDigest,
		ErrorCode:          value.errorCode,
		Evidence:           evidenceToWire(value.evidence),
		NFTBinaryDigest:    value.nftBinaryDigest,
		NFTBinaryPath:      value.nftBinaryPath,
		NFTVersion:         value.nftVersion,
		Passed:             value.passed,
		RequestDigest:      value.requestDigest,
		SchemaVersion:      ResponseSchemaVersion,
	}
	return marshalBounded(wire)
}

func decodeResponse(payload []byte) (response, error) {
	if !validJSONPayload(payload) {
		return response{}, reject(ErrorResponseInvalid)
	}
	var wire responseWire
	if err := decodeExact(payload, &wire); err != nil || wire.SchemaVersion != ResponseSchemaVersion {
		return response{}, reject(ErrorResponseInvalid)
	}
	value := response{
		baseContractDigest: wire.BaseContractDigest,
		errorCode:          wire.ErrorCode,
		evidence:           evidenceFromWire(wire.Evidence),
		nftBinaryDigest:    wire.NFTBinaryDigest,
		nftBinaryPath:      wire.NFTBinaryPath,
		nftVersion:         wire.NFTVersion,
		passed:             wire.Passed,
		requestDigest:      wire.RequestDigest,
	}
	if !validResponse(value) {
		return response{}, reject(ErrorResponseInvalid)
	}
	return value, nil
}

func validResponse(value response) bool {
	if value.baseContractDigest != nftcheck.PinnedBaseContractDigest ||
		!digestPattern.MatchString(value.nftBinaryDigest) ||
		value.nftBinaryPath != nftcheck.FixedNFTBinaryPath ||
		!validNFTVersion(value.nftVersion) ||
		!digestPattern.MatchString(value.requestDigest) ||
		!validEvidence(value.evidence) {
		return false
	}
	if value.passed {
		return value.errorCode == "" && value.evidence.CanonicalDigest != "" &&
			value.evidence.BaseContractDigest == nftcheck.PinnedBaseContractDigest &&
			value.evidence.NFTVersion == value.nftVersion &&
			value.evidence.VersionExitStatus == 0 && value.evidence.SyntaxExitStatus == 0
	}
	return value.errorCode != "" && validRemoteErrorCode(value.errorCode)
}

func validEvidence(value nftcheck.Evidence) bool {
	if value.GateVersion != nftcheck.GateVersion || value.NFTBinaryPath != nftcheck.FixedNFTBinaryPath ||
		value.VersionArguments != [1]string{"--version"} ||
		value.SyntaxArguments != [3]string{"--check", "-f", "-"} ||
		value.VersionExitStatus < -1 || value.VersionExitStatus > 255 ||
		value.SyntaxExitStatus < -1 || value.SyntaxExitStatus > 255 ||
		value.VersionOutputByteCount > nftcheck.MaxProcessOutput ||
		value.SyntaxOutputByteCount > nftcheck.MaxProcessOutput {
		return false
	}
	for _, value := range []string{value.CanonicalDigest, value.BaseContractDigest, value.VersionOutputDigest, value.SyntaxOutputDigest} {
		if value != "" && !digestPattern.MatchString(value) {
			return false
		}
	}
	if (value.VersionOutputDigest == "" && value.VersionOutputByteCount != 0) ||
		(value.SyntaxOutputDigest == "" && value.SyntaxOutputByteCount != 0) ||
		(value.NFTVersion != "" && !validNFTVersion(value.NFTVersion)) {
		return false
	}
	return true
}

func validRemoteErrorCode(value string) bool {
	switch value {
	case string(nftcheck.ErrorInvalidInput), string(nftcheck.ErrorCandidateInvalid),
		string(nftcheck.ErrorCandidateDigest), string(nftcheck.ErrorCandidateMismatch),
		string(nftcheck.ErrorBaseDigest), string(nftcheck.ErrorBaseContract),
		string(nftcheck.ErrorRunnerUnavailable), string(nftcheck.ErrorInvocationMismatch),
		string(nftcheck.ErrorVersionCommand), string(nftcheck.ErrorVersionInvalid),
		string(nftcheck.ErrorVersionMismatch), string(nftcheck.ErrorOutputLimit),
		string(nftcheck.ErrorSyntaxRejected), string(nftcheck.ErrorCancelled),
		string(nftcheck.ErrorTimeout), string(nftcheck.ErrorUnsupportedPlatform),
		string(ErrorRequestReplayed), string(ErrorReplayCacheFull):
		return true
	default:
		return false
	}
}

func evidenceToWire(value nftcheck.Evidence) evidenceWire {
	return evidenceWire{
		BaseContractDigest: value.BaseContractDigest, CanonicalDigest: value.CanonicalDigest,
		GateVersion: value.GateVersion, NFTBinaryPath: value.NFTBinaryPath, NFTVersion: value.NFTVersion,
		SyntaxArguments: value.SyntaxArguments, SyntaxExitStatus: value.SyntaxExitStatus,
		SyntaxOutputByteCount: value.SyntaxOutputByteCount, SyntaxOutputDigest: value.SyntaxOutputDigest,
		VersionArguments: value.VersionArguments, VersionExitStatus: value.VersionExitStatus,
		VersionOutputByteCount: value.VersionOutputByteCount, VersionOutputDigest: value.VersionOutputDigest,
	}
}

func evidenceFromWire(value evidenceWire) nftcheck.Evidence {
	return nftcheck.Evidence{
		BaseContractDigest: value.BaseContractDigest, CanonicalDigest: value.CanonicalDigest,
		GateVersion: value.GateVersion, NFTBinaryPath: value.NFTBinaryPath, NFTVersion: value.NFTVersion,
		SyntaxArguments: value.SyntaxArguments, SyntaxExitStatus: value.SyntaxExitStatus,
		SyntaxOutputByteCount: value.SyntaxOutputByteCount, SyntaxOutputDigest: value.SyntaxOutputDigest,
		VersionArguments: value.VersionArguments, VersionExitStatus: value.VersionExitStatus,
		VersionOutputByteCount: value.VersionOutputByteCount, VersionOutputDigest: value.VersionOutputDigest,
	}
}

func initialEvidence(candidateDigest string) nftcheck.Evidence {
	return nftcheck.Evidence{
		GateVersion: nftcheck.GateVersion, CanonicalDigest: candidateDigest,
		BaseContractDigest: nftcheck.PinnedBaseContractDigest,
		NFTBinaryPath:      nftcheck.FixedNFTBinaryPath,
		VersionArguments:   [1]string{"--version"}, SyntaxArguments: [3]string{"--check", "-f", "-"},
		VersionExitStatus: -1, SyntaxExitStatus: -1,
	}
}

func marshalBounded(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > ipc.MaxFramePayloadBytes || !utf8.Valid(payload) {
		return nil, reject(ErrorResponseInvalid)
	}
	return payload, nil
}

func decodeExact(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, payload) {
		return errors.New("non-canonical or duplicate JSON object")
	}
	return nil
}

func validJSONPayload(payload []byte) bool {
	return len(payload) > 0 && len(payload) <= ipc.MaxFramePayloadBytes && utf8.Valid(payload) &&
		!bytes.HasPrefix(payload, []byte{0xef, 0xbb, 0xbf}) && json.Valid(payload)
}

func validCandidateEnvelope(value []byte) bool {
	if len(value) == 0 || len(value) > nftcheck.MaxCandidateBytes || !utf8.Valid(value) ||
		bytes.HasPrefix(value, []byte{0xef, 0xbb, 0xbf}) || value[len(value)-1] != '\n' {
		return false
	}
	for index, current := range value {
		if current > 0x7e || current == 0 || current == '\r' || current == '\t' ||
			(current == '\n' && index != len(value)-1) || (current < 0x20 && current != '\n') {
			return false
		}
	}
	return true
}

func validNFTVersion(value string) bool {
	return versionPattern.MatchString(value)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requestDigest(payload []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(requestDigestDomain))
	_, _ = hash.Write(payload)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
