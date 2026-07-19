package hil

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Reason is the typed human-authored hil-reason-v1 value. CheckReason NFC
// normalizes ReasonText before hashing; ParseCanonicalReason never silently
// repairs already serialized bytes.
type Reason struct {
	SchemaVersion string
	ReasonCode    ReasonCode
	ReasonText    string
}

func (Reason) String() string     { return "hil.Reason{text:[REDACTED]}" }
func (r Reason) GoString() string { return r.String() }

type CheckedReason struct {
	value     Reason
	canonical []byte
	digest    string
}

func (CheckedReason) String() string     { return "hil.CheckedReason{text:[REDACTED]}" }
func (r CheckedReason) GoString() string { return r.String() }

func (r CheckedReason) Value() Reason          { return r.value }
func (r CheckedReason) CanonicalBytes() []byte { return bytes.Clone(r.canonical) }
func (r CheckedReason) DigestInput() []byte    { return bytes.Clone(r.canonical) }
func (r CheckedReason) Digest() string         { return r.digest }

func validReasonCode(value ReasonCode) bool {
	switch value {
	case ReasonThreatConfirmed, ReasonFalsePositive, ReasonBusinessException,
		ReasonEmergencyRevoke, ReasonOperatorRequest, ReasonOther:
		return true
	default:
		return false
	}
}

func CheckReason(value Reason) (CheckedReason, error) {
	if value.SchemaVersion != ReasonSchemaVersion {
		return CheckedReason{}, reject(ErrorSchema)
	}
	if !validReasonCode(value.ReasonCode) || len(value.ReasonText) == 0 ||
		len(value.ReasonText) > MaxReasonBytes || !utf8.ValidString(value.ReasonText) {
		return CheckedReason{}, reject(ErrorReason)
	}
	value.ReasonText = norm.NFC.String(value.ReasonText)
	if strings.TrimSpace(value.ReasonText) == "" || utf8.RuneCountInString(value.ReasonText) > MaxReasonRunes {
		return CheckedReason{}, reject(ErrorReason)
	}
	for _, r := range value.ReasonText {
		// The JSON schema permits a few whitespace controls, but the durable
		// hil_reasons table forbids every control character. Enforce the
		// stricter intersection so a checked value is always persistable.
		if r <= 0x1f || r == 0x7f {
			return CheckedReason{}, reject(ErrorReason)
		}
	}
	canonical := marshalReasonJCS(value)
	if len(canonical) > MaxReasonBytes {
		return CheckedReason{}, reject(ErrorReason)
	}
	return CheckedReason{value: value, canonical: canonical, digest: digestBytes(canonical)}, nil
}

type reasonWire struct {
	ReasonCode    ReasonCode `json:"reason_code"`
	ReasonText    string     `json:"reason_text"`
	SchemaVersion string     `json:"schema_version"`
}

func ParseCanonicalReason(data []byte) (CheckedReason, error) {
	var wire reasonWire
	if err := decodeStrict(data, MaxReasonBytes, &wire); err != nil {
		return CheckedReason{}, err
	}
	checked, err := CheckReason(Reason{
		SchemaVersion: wire.SchemaVersion,
		ReasonCode:    wire.ReasonCode,
		ReasonText:    wire.ReasonText,
	})
	if err != nil {
		return CheckedReason{}, err
	}
	if !norm.NFC.IsNormalString(wire.ReasonText) || !bytes.Equal(data, checked.canonical) {
		return CheckedReason{}, reject(ErrorCanonical)
	}
	return checked, nil
}

func marshalReasonJCS(value Reason) []byte {
	result := make([]byte, 0, 128+len(value.ReasonText))
	result = append(result, `{"reason_code":`...)
	result = appendJCSString(result, string(value.ReasonCode))
	result = append(result, `,"reason_text":`...)
	result = appendJCSString(result, value.ReasonText)
	result = append(result, `,"schema_version":`...)
	result = appendJCSString(result, value.SchemaVersion)
	return append(result, '}')
}
