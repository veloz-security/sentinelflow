package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/devwooops/sentinelflow/internal/hil"
)

type artifactBindingInput struct {
	operation                hil.Operation
	policyVersion            uint32
	targetIPv4               string
	ttlSeconds               uint32
	policyDigest             string
	generatedArtifactDigest  string
	canonicalArtifactDigest  string
	evidenceSnapshotDigest   string
	validationSnapshotDigest string
}

type decisionInput struct {
	artifact       artifactBindingInput
	challenge      json.RawMessage
	challengeNonce string
	reason         hil.CheckedReason
}

func (decisionInput) String() string {
	return "adminapi.decisionInput{challenge:[REDACTED],nonce:[REDACTED],reason:[REDACTED]}"
}

func (input decisionInput) GoString() string { return input.String() }

func decodeChallengeRequest(request *http.Request) (artifactBindingInput, error) {
	body, err := readStrictBodyWithLimit(request, MaxHILRequestBodyBytes)
	if err != nil {
		return artifactBindingInput{}, err
	}
	defer clear(body)
	return decodeArtifactBinding(body, nil)
}

func decodeDecisionRequest(request *http.Request) (decisionInput, error) {
	body, err := readStrictBodyWithLimit(request, MaxHILRequestBodyBytes)
	if err != nil {
		return decisionInput{}, err
	}
	defer clear(body)
	result := decisionInput{}
	fields := map[string]func(*json.Decoder) error{
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
		"reason": func(decoder *json.Decoder) error {
			var raw json.RawMessage
			if decodeErr := decoder.Decode(&raw); decodeErr != nil {
				return decodeErr
			}
			defer clear(raw)
			checked, decodeErr := decodeReason(raw)
			if decodeErr == nil {
				result.reason = checked
			}
			return decodeErr
		},
	}
	artifact, err := decodeArtifactBinding(body, fields)
	if err != nil || len(result.challenge) == 0 || result.challengeNonce == "" || result.reason.Digest() == "" {
		clear(result.challenge)
		return decisionInput{}, errInvalidRequest
	}
	result.artifact = artifact
	return result, nil
}

func decodeArtifactBinding(body []byte, additional map[string]func(*json.Decoder) error) (artifactBindingInput, error) {
	result := artifactBindingInput{}
	fields := map[string]func(*json.Decoder) error{
		"operation": func(decoder *json.Decoder) error {
			value, err := decodeString(decoder, 7)
			if err == nil {
				result.operation = hil.Operation(value)
			}
			clear(value)
			return err
		},
		"policy_version": func(decoder *json.Decoder) error {
			return decoder.Decode(&result.policyVersion)
		},
		"target_ipv4": func(decoder *json.Decoder) error {
			value, err := decodeString(decoder, 15)
			if err == nil {
				result.targetIPv4 = string(value)
			}
			clear(value)
			return err
		},
		"ttl_seconds": func(decoder *json.Decoder) error {
			return decoder.Decode(&result.ttlSeconds)
		},
		"policy_digest": func(decoder *json.Decoder) error {
			return decodeBindingString(decoder, &result.policyDigest)
		},
		"generated_artifact_digest": func(decoder *json.Decoder) error {
			return decodeBindingString(decoder, &result.generatedArtifactDigest)
		},
		"canonical_artifact_digest": func(decoder *json.Decoder) error {
			return decodeBindingString(decoder, &result.canonicalArtifactDigest)
		},
		"evidence_snapshot_digest": func(decoder *json.Decoder) error {
			return decodeBindingString(decoder, &result.evidenceSnapshotDigest)
		},
		"validation_snapshot_digest": func(decoder *json.Decoder) error {
			return decodeBindingString(decoder, &result.validationSnapshotDigest)
		},
	}
	for name, decode := range additional {
		fields[name] = decode
	}
	if err := decodeObject(body, fields); err != nil {
		return artifactBindingInput{}, errInvalidRequest
	}
	return result, nil
}

func decodeBindingString(decoder *json.Decoder, destination *string) error {
	value, err := decodeString(decoder, 71)
	if err == nil {
		*destination = string(value)
	}
	clear(value)
	return err
}

func decodeReason(raw []byte) (hil.CheckedReason, error) {
	var schemaVersion, reasonText string
	var reasonCode hil.ReasonCode
	err := decodeObject(raw, map[string]func(*json.Decoder) error{
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
	})
	if err != nil {
		return hil.CheckedReason{}, errInvalidRequest
	}
	checked, err := hil.CheckReason(hil.Reason{
		SchemaVersion: schemaVersion, ReasonCode: reasonCode, ReasonText: reasonText,
	})
	if err != nil {
		return hil.CheckedReason{}, err
	}
	return checked, nil
}
