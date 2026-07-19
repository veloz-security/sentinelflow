package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
	"golang.org/x/text/unicode/norm"
)

type revocationBindingInput struct {
	actionVersion     uint32
	targetIPv4        string
	originalAddDigest string
}

type revocationDecisionInput struct {
	revocationBindingInput
	challenge               json.RawMessage
	challengeNonce          string
	canonicalRevokeArtifact []byte
	policyID                string
	policyVersion           uint32
	reason                  hil.CheckedReason
}

func (revocationDecisionInput) String() string {
	return "adminapi.revocationDecisionInput{challenge:[REDACTED],nonce:[REDACTED],artifact:[REDACTED],reason:[REDACTED]}"
}

func (input revocationDecisionInput) GoString() string { return input.String() }

func decodeRevocationChallengeRequest(request *http.Request) (revocationBindingInput, error) {
	body, err := readStrictBodyWithLimit(request, MaxHILRequestBodyBytes)
	if err != nil {
		return revocationBindingInput{}, err
	}
	defer clear(body)
	return decodeRevocationBinding(body, nil)
}

func decodeRevocationDecisionRequest(request *http.Request) (revocationDecisionInput, error) {
	body, err := readStrictBodyWithLimit(request, MaxHILRequestBodyBytes)
	if err != nil {
		return revocationDecisionInput{}, err
	}
	defer clear(body)
	result := revocationDecisionInput{}
	additional := map[string]func(*json.Decoder) error{
		"challenge": func(decoder *json.Decoder) error {
			return decoder.Decode(&result.challenge)
		},
		"challenge_nonce": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, 64)
			if decodeErr == nil {
				result.challengeNonce = string(value)
			}
			clear(value)
			return decodeErr
		},
		"canonical_revoke_artifact": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, lifecycleartifact.MaxRevokeArtifactBytes)
			if decodeErr == nil {
				result.canonicalRevokeArtifact = value
			}
			return decodeErr
		},
		"policy_id": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, 36)
			if decodeErr == nil {
				result.policyID = string(value)
			}
			clear(value)
			return decodeErr
		},
		"policy_version": func(decoder *json.Decoder) error {
			return decoder.Decode(&result.policyVersion)
		},
		"reason": func(decoder *json.Decoder) error {
			var raw json.RawMessage
			if decodeErr := decoder.Decode(&raw); decodeErr != nil {
				return decodeErr
			}
			defer clear(raw)
			checked, decodeErr := decodeRevocationReason(raw)
			if decodeErr == nil {
				result.reason = checked
			}
			return decodeErr
		},
	}
	binding, err := decodeRevocationBinding(body, additional)
	if err != nil || len(result.challenge) == 0 || result.challengeNonce == "" ||
		len(result.canonicalRevokeArtifact) == 0 || result.policyID == "" ||
		result.policyVersion == 0 || result.reason.Digest() == "" {
		clear(result.challenge)
		clear(result.canonicalRevokeArtifact)
		return revocationDecisionInput{}, errInvalidRequest
	}
	result.revocationBindingInput = binding
	return result, nil
}

func decodeRevocationBinding(
	body []byte,
	additional map[string]func(*json.Decoder) error,
) (revocationBindingInput, error) {
	result := revocationBindingInput{}
	fields := map[string]func(*json.Decoder) error{
		"action_version": func(decoder *json.Decoder) error {
			return decoder.Decode(&result.actionVersion)
		},
		"target_ipv4": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, 15)
			if decodeErr == nil {
				result.targetIPv4 = string(value)
			}
			clear(value)
			return decodeErr
		},
		"original_add_digest": func(decoder *json.Decoder) error {
			return decodeBindingString(decoder, &result.originalAddDigest)
		},
	}
	for name, decode := range additional {
		fields[name] = decode
	}
	if err := decodeObject(body, fields); err != nil {
		return revocationBindingInput{}, errInvalidRequest
	}
	return result, nil
}

func decodeRevocationReason(raw []byte) (hil.CheckedReason, error) {
	var schemaVersion, reasonText string
	var reasonCode hil.ReasonCode
	if err := decodeObject(raw, map[string]func(*json.Decoder) error{
		"schema_version": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, len(hil.ReasonSchemaVersion))
			if decodeErr == nil {
				schemaVersion = string(value)
			}
			clear(value)
			return decodeErr
		},
		"reason_code": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, 32)
			if decodeErr == nil {
				reasonCode = hil.ReasonCode(value)
			}
			clear(value)
			return decodeErr
		},
		"reason_text": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, hil.MaxReasonBytes)
			if decodeErr == nil {
				reasonText = string(value)
			}
			clear(value)
			return decodeErr
		},
	}); err != nil || !norm.NFC.IsNormalString(reasonText) {
		return hil.CheckedReason{}, errInvalidRequest
	}
	switch reasonCode {
	case hil.ReasonEmergencyRevoke, hil.ReasonOperatorRequest, hil.ReasonOther:
	default:
		return hil.CheckedReason{}, errInvalidRequest
	}
	checked, err := hil.CheckReason(hil.Reason{
		SchemaVersion: schemaVersion,
		ReasonCode:    reasonCode,
		ReasonText:    reasonText,
	})
	if err != nil || checked.Value().ReasonText != reasonText {
		return hil.CheckedReason{}, errInvalidRequest
	}
	return checked, nil
}
