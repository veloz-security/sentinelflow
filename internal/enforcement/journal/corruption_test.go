package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

func TestRecordPayloadMatchesFrozenSchemaAndDigestChain(t *testing.T) {
	f := newFixture(t)
	startFrame, terminalFrame := validFrames(t, f)
	frames := [][]byte{startFrame, terminalFrame}
	expectedKeys := map[string]struct{}{
		"artifact_b64url": {}, "artifact_digest": {}, "capability_digest": {}, "capability_id": {},
		"capability_jcs_b64url": {}, "capability_signature_b64url": {}, "deadline": {},
		"journal_sequence": {}, "operation": {}, "owned_schema_digest": {}, "phase": {},
		"previous_record_digest": {}, "received_at": {}, "record_checksum": {}, "schema_version": {},
		"target_ipv4": {}, "terminal_result_digest": {}, "terminal_result_jcs_b64url": {},
		"terminal_result_signature_b64url": {},
	}
	previous := ""
	for index, frame := range frames {
		decoded, err := decodeFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(decoded.payload, &fields); err != nil || len(fields) != len(expectedKeys) {
			t.Fatalf("record %d does not have frozen schema shape: fields=%d err=%v", index, len(fields), err)
		}
		for key := range fields {
			if _, ok := expectedKeys[key]; !ok {
				t.Fatalf("record %d has non-contract field %q", index, key)
			}
		}
		payload, digest, err := parseRecordPayload(decoded.payload, decoded.recordType, uint64(index+1), previous)
		if err != nil {
			t.Fatal(err)
		}
		if payload.SchemaVersion != SchemaRecordV1 {
			t.Fatalf("record %d schema changed: %s", index, payload.SchemaVersion)
		}
		preimage, err := json.Marshal(checksumPayload(payload))
		if err != nil || payload.RecordChecksum != digestPayload(preimage) {
			t.Fatalf("record %d checksum mismatch: err=%v", index, err)
		}
		if index == 0 && payload.PreviousRecordDigest != nil {
			t.Fatal("first record unexpectedly has a predecessor")
		}
		if index == 1 && (payload.PreviousRecordDigest == nil || *payload.PreviousRecordDigest != previous) {
			t.Fatal("terminal record does not chain the complete started record")
		}
		previous = digest
	}
}

func TestEveryFrameTruncationAndChecksumTamperRejected(t *testing.T) {
	f := newFixture(t)
	path := journalPath(t)
	j, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Begin(f.signed, f.received, f.deadline); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	frame := readJournal(t, path)
	if _, err := decodeFrame(frame); err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(frame); cut++ {
		if _, err := decodeFrame(frame[:cut]); err == nil {
			t.Fatalf("truncation at byte %d accepted", cut)
		}
	}
	positions := []int{0, 8, 9, 10, 12, 20, frameHeaderBytes, len(frame) / 2, len(frame) - 1}
	for _, position := range positions {
		tampered := append([]byte(nil), frame...)
		tampered[position] ^= 1
		if _, err := decodeFrame(tampered); err == nil {
			t.Fatalf("tamper at byte %d accepted", position)
		}
	}
	if _, err := encodeFrame(9, 1, []byte("x")); err == nil {
		t.Fatal("unknown record type encoded")
	}
	if _, err := encodeFrame(recordStarted, 0, []byte("x")); err == nil {
		t.Fatal("zero sequence encoded")
	}
	if _, err := encodeFrame(recordStarted, 1, bytes.Repeat([]byte{'x'}, MaxPayloadBytes+1)); err == nil {
		t.Fatal("oversized payload encoded")
	}
}

func TestStartupCrashBoundariesFailWithoutRepair(t *testing.T) {
	f := newFixture(t)
	path := journalPath(t)
	j, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	begin, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := begin.Permit()
	result := f.signedResult(t, 1, capability.ClassificationApplied, f.received.Add(time.Millisecond), func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	if _, _, err := j.Complete(result); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	all := readJournal(t, path)
	frames := splitFrames(t, all)
	firstEnd := len(frames[0])
	cuts := []int{1, 7, frameHeaderBytes - 1, frameHeaderBytes, firstEnd / 2, firstEnd - 1, firstEnd + 1, firstEnd + frameHeaderBytes - 1, len(all) - 1}
	for _, cut := range cuts {
		t.Run("cut-"+itoa(cut), func(t *testing.T) {
			candidate := journalPath(t)
			writeJournal(t, candidate, all[:cut])
			before := readJournal(t, candidate)
			if opened, err := Open(f.options(candidate)); err == nil {
				opened.Close()
				t.Fatal("torn journal accepted")
			}
			if !bytes.Equal(before, readJournal(t, candidate)) {
				t.Fatal("startup repaired or truncated torn journal")
			}
		})
	}
}

func TestStartupRejectsSequenceVersionDuplicatesAndOrphans(t *testing.T) {
	f := newFixture(t)
	startFrame, terminalFrame := validFrames(t, f)
	decodedStart, _ := decodeFrame(startFrame)
	decodedTerminal, _ := decodeFrame(terminalFrame)
	var startRecord recordPayload
	if err := strictPayload(decodedStart.payload, &startRecord); err != nil {
		t.Fatal(err)
	}
	var terminalRecord recordPayload
	if err := strictPayload(decodedTerminal.payload, &terminalRecord); err != nil {
		t.Fatal(err)
	}
	startDigest := digestPayload(decodedStart.payload)
	terminalDigest := digestPayload(decodedTerminal.payload)
	duplicateStart := startRecord
	duplicateStart.JournalSequence = 2
	duplicateStart.PreviousRecordDigest = optionalDigest(startDigest)
	duplicateStartPayload := resealRecord(t, duplicateStart)
	duplicateTerminal := terminalRecord
	duplicateTerminal.JournalSequence = 3
	duplicateTerminal.PreviousRecordDigest = optionalDigest(terminalDigest)
	duplicateTerminalPayload := resealRecord(t, duplicateTerminal)

	tests := []struct {
		name string
		data []byte
		code ErrorCode
	}{
		{"unknown version", mutateVersion(startFrame, 2), ErrorVersion},
		{"sequence gap", mustFrame(t, recordStarted, 2, decodedStart.payload), ErrorSequence},
		{"duplicate start", append(append([]byte(nil), startFrame...), mustFrame(t, recordStarted, 2, duplicateStartPayload)...), ErrorConflict},
		{"terminal without start", mustFrame(t, recordTerminal, 1, decodedTerminal.payload), ErrorCorrupt},
		{"duplicate terminal", append(append(append([]byte(nil), startFrame...), terminalFrame...), mustFrame(t, recordTerminal, 3, duplicateTerminalPayload)...), ErrorDuplicateTerminal},
		{"unknown payload field", mustFrame(t, recordStarted, 1, append(decodedStart.payload[:len(decodedStart.payload)-1], []byte(`,"extra":true}`)...)), ErrorCorrupt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := journalPath(t)
			writeJournal(t, path, test.data)
			_, err := Open(f.options(path))
			if err == nil {
				t.Fatal("invalid journal accepted")
			}
			assertCode(t, err, test.code)
		})
	}
}

func TestPayloadTamperWithValidFrameChecksumFailsVerification(t *testing.T) {
	f := newFixture(t)
	startFrame, terminalFrame := validFrames(t, f)
	startDecoded, _ := decodeFrame(startFrame)
	terminalDecoded, _ := decodeFrame(terminalFrame)

	var start recordPayload
	if err := strictPayload(startDecoded.payload, &start); err != nil {
		t.Fatal(err)
	}
	start.ArtifactB64URL = encodeBytes([]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.21 timeout 30m }\n"))
	badArtifact := resealRecord(t, start)

	var badSignature recordPayload
	if err := strictPayload(startDecoded.payload, &badSignature); err != nil {
		t.Fatal(err)
	}
	signature, _ := decodeBytes(badSignature.CapabilitySignatureB64URL, 64)
	signature[0] ^= 1
	badSignature.CapabilitySignatureB64URL = encodeBytes(signature)
	badSignaturePayload := resealRecord(t, badSignature)

	var terminal recordPayload
	if err := strictPayload(terminalDecoded.payload, &terminal); err != nil {
		t.Fatal(err)
	}
	resultSignature, _ := decodeBytes(*terminal.TerminalResultSignatureB64URL, 64)
	resultSignature[len(resultSignature)-1] ^= 1
	encodedResultSignature := encodeBytes(resultSignature)
	terminal.TerminalResultSignatureB64URL = &encodedResultSignature
	badTerminalPayload := resealRecord(t, terminal)

	tests := []struct {
		name string
		data []byte
	}{
		{"artifact", mustFrame(t, recordStarted, 1, badArtifact)},
		{"capability signature", mustFrame(t, recordStarted, 1, badSignaturePayload)},
		{"result signature", append(append([]byte(nil), startFrame...), mustFrame(t, recordTerminal, 2, badTerminalPayload)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := journalPath(t)
			writeJournal(t, path, test.data)
			_, err := Open(f.options(path))
			if err == nil {
				t.Fatal("tampered signed payload accepted")
			}
			assertCode(t, err, ErrorVerification)
		})
	}
}

func TestPreviousRecordDigestChainRejectsReorderingAndRewrite(t *testing.T) {
	f := newFixture(t)
	startFrame, terminalFrame := validFrames(t, f)
	terminalDecoded, _ := decodeFrame(terminalFrame)
	var terminal recordPayload
	if err := strictPayload(terminalDecoded.payload, &terminal); err != nil {
		t.Fatal(err)
	}
	wrongPrevious := testDigest("wrong previous record")
	terminal.PreviousRecordDigest = &wrongPrevious
	tamperedTerminal := mustFrame(t, recordTerminal, 2, resealRecord(t, terminal))
	path := journalPath(t)
	writeJournal(t, path, append(append([]byte(nil), startFrame...), tamperedTerminal...))
	if _, err := Open(f.options(path)); err == nil {
		t.Fatal("rewritten previous-record digest accepted")
	} else {
		assertCode(t, err, ErrorCorrupt)
	}
}

func TestRuntimeConflictingTerminalRejected(t *testing.T) {
	f := newFixture(t)
	j, err := Open(f.options(journalPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	begin, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := begin.Permit()
	applied := f.signedResult(t, 1, capability.ClassificationApplied, f.received.Add(time.Millisecond), func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	if _, _, err := j.Complete(applied); err != nil {
		t.Fatal(err)
	}
	conflict := f.signedResult(t, 1, capability.ClassificationRecoveredActive, f.received.Add(2*time.Millisecond), func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	if _, _, err := j.Complete(conflict); err == nil {
		t.Fatal("conflicting terminal accepted")
	} else {
		assertCode(t, err, ErrorDuplicateTerminal)
	}
}

func validFrames(t *testing.T, f fixture) ([]byte, []byte) {
	t.Helper()
	path := journalPath(t)
	j, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	begin, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := begin.Permit()
	result := f.signedResult(t, 1, capability.ClassificationApplied, f.received.Add(time.Millisecond), func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	if _, _, err := j.Complete(result); err != nil {
		t.Fatal(err)
	}
	j.Close()
	frames := splitFrames(t, readJournal(t, path))
	return frames[0], frames[1]
}

func splitFrames(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	for len(data) > 0 {
		if len(data) < frameHeaderBytes {
			t.Fatal("invalid fixture frame")
		}
		length := frameHeaderBytes + int(binary.BigEndian.Uint32(data[20:24])) + checksumBytes
		if length > len(data) {
			t.Fatal("truncated fixture frame")
		}
		frames = append(frames, append([]byte(nil), data[:length]...))
		data = data[length:]
	}
	return frames
}

func mustFrame(t *testing.T, recordType byte, sequence uint64, payload []byte) []byte {
	t.Helper()
	frame, err := encodeFrame(recordType, sequence, payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func resealRecord(t *testing.T, payload recordPayload) []byte {
	t.Helper()
	payload.RecordChecksum = ""
	encoded, _, err := marshalRecordPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mutateVersion(frame []byte, version byte) []byte {
	result := append([]byte(nil), frame...)
	result[8] = version
	payloadLength := int(binary.BigEndian.Uint32(result[20:24]))
	sum := sha256.Sum256(result[:frameHeaderBytes+payloadLength])
	copy(result[frameHeaderBytes+payloadLength:], sum[:])
	return result
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [32]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
