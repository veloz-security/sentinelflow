package hil

import (
	"bytes"
	"strings"
	"testing"
)

func TestReasonNFCJCSAndDefensiveCopies(t *testing.T) {
	checked, err := CheckReason(Reason{
		SchemaVersion: ReasonSchemaVersion,
		ReasonCode:    ReasonThreatConfirmed,
		ReasonText:    "Cafe\u0301 <script>\u2028line",
	})
	if err != nil {
		t.Fatalf("check reason: %v", err)
	}
	want := []byte(`{"reason_code":"threat_confirmed","reason_text":"Café <script> line","schema_version":"hil-reason-v1"}`)
	if !bytes.Equal(checked.CanonicalBytes(), want) {
		t.Fatalf("canonical = %q, want %q", checked.CanonicalBytes(), want)
	}
	if checked.Digest() != digestBytes(want) || !bytes.Equal(checked.DigestInput(), want) {
		t.Fatal("reason digest is not bound to exact JCS bytes")
	}
	parsed, err := ParseCanonicalReason(want)
	if err != nil || parsed.Digest() != checked.Digest() {
		t.Fatalf("parse canonical reason: digest=%q err=%v", parsed.Digest(), err)
	}
	copyBytes := checked.CanonicalBytes()
	copyBytes[0] ^= 1
	if bytes.Equal(copyBytes, checked.CanonicalBytes()) {
		t.Fatal("canonical reason accessor leaked mutable storage")
	}
	if strings.Contains(string(checked.CanonicalBytes()), `\u003c`) || strings.Contains(string(checked.CanonicalBytes()), `\u2028`) {
		t.Fatal("reason used non-JCS HTML/JSONP escaping")
	}
}

func TestReasonRejectsInvalidAndNonCanonicalValues(t *testing.T) {
	tests := []struct {
		name  string
		value Reason
		code  ErrorCode
	}{
		{"schema", Reason{SchemaVersion: "v2", ReasonCode: ReasonOther, ReasonText: "ok"}, ErrorSchema},
		{"code", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: "unknown", ReasonText: "ok"}, ErrorReason},
		{"empty", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther}, ErrorReason},
		{"whitespace", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: " \t\n"}, ErrorReason},
		{"control", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: "bad\x00"}, ErrorReason},
		{"newline", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: "bad\nline"}, ErrorReason},
		{"delete", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: "bad\x7f"}, ErrorReason},
		{"too many runes", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: strings.Repeat("가", MaxReasonRunes+1)}, ErrorReason},
		{"too many bytes", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: strings.Repeat("a", MaxReasonBytes+1)}, ErrorReason},
		{"invalid utf8", Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonOther, ReasonText: string([]byte{0xff})}, ErrorReason},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CheckReason(test.value); !IsCode(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}

	canonical := []byte(`{"reason_code":"other","reason_text":"ok","schema_version":"hil-reason-v1"}`)
	mutations := [][]byte{
		[]byte(`{ "reason_code":"other","reason_text":"ok","schema_version":"hil-reason-v1"}`),
		[]byte(`{"reason_text":"ok","reason_code":"other","schema_version":"hil-reason-v1"}`),
		[]byte(`{"reason_code":"other","reason_code":"other","reason_text":"ok","schema_version":"hil-reason-v1"}`),
		[]byte(`{"reason_code":"other","reason_text":"ok","schema_version":"hil-reason-v1","unknown":1}`),
		append(bytes.Clone(canonical), '\n'),
		bytes.Repeat([]byte{'x'}, MaxReasonBytes+1),
	}
	for index, mutation := range mutations {
		if _, err := ParseCanonicalReason(mutation); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
	decomposed := []byte(`{"reason_code":"other","reason_text":"Cafe\u0301","schema_version":"hil-reason-v1"}`)
	if _, err := ParseCanonicalReason(decomposed); !IsCode(err, ErrorCanonical) {
		t.Fatalf("decomposed parse error = %v", err)
	}
}
