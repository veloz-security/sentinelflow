package journal

import (
	"encoding/binary"
	"sort"
)

// ValidationEntry is the redacted authenticated identity of one complete or
// started-only journal lifecycle. It intentionally exposes no artifact,
// signature, target, actor, or canonical payload bytes.
type ValidationEntry struct {
	CapabilityID     string
	CapabilityDigest string
	ArtifactDigest   string
	StartedSequence  uint64
	Terminal         bool
	TerminalSequence uint64
	ResultDigest     string
}

// ValidationSummary is produced only after every frame, checksum, chain link,
// capability signature, result signature, and capability/result binding has
// passed the same parser used during executor startup.
type ValidationSummary struct {
	Entries      []ValidationEntry
	LastSequence uint64
}

// ValidateBytes performs a read-only startup-equivalent scan. Unlike Open it
// never creates, locks, truncates, repairs, appends, or fsyncs a journal, so it
// is safe to use while the recovery offline fence is held.
func ValidateBytes(
	contents []byte,
	capabilityVerifier CapabilityVerifier,
	resultVerifier ResultVerifier,
) (ValidationSummary, error) {
	if capabilityVerifier == nil || resultVerifier == nil ||
		capabilityVerifier.KeyID() == "" || resultVerifier.KeyID() == "" ||
		resultVerifier.ExecutorID() == "" {
		return ValidationSummary{}, reject(ErrorVerification)
	}
	if len(contents) > MaxJournalBytes {
		return ValidationSummary{}, reject(ErrorTooLarge)
	}
	index := &Journal{
		capabilityVerifier: capabilityVerifier,
		resultVerifier:     resultVerifier,
		entries:            make(map[string]*startedRecord),
	}
	offset := 0
	expectedSequence := uint64(1)
	previousRecordDigest := ""
	for offset < len(contents) {
		remaining := len(contents) - offset
		if remaining < frameHeaderBytes+checksumBytes {
			return ValidationSummary{}, reject(ErrorCorrupt)
		}
		header := contents[offset : offset+frameHeaderBytes]
		payloadLength := binary.BigEndian.Uint32(header[20:24])
		if payloadLength == 0 || payloadLength > MaxPayloadBytes {
			return ValidationSummary{}, reject(ErrorCorrupt)
		}
		length := frameHeaderBytes + int(payloadLength) + checksumBytes
		if length > remaining || length > MaxFrameBytes {
			return ValidationSummary{}, reject(ErrorCorrupt)
		}
		decoded, err := decodeFrame(contents[offset : offset+length])
		if err != nil {
			return ValidationSummary{}, err
		}
		if decoded.sequence != expectedSequence {
			return ValidationSummary{}, reject(ErrorSequence)
		}
		payload, recordDigest, err := parseRecordPayload(
			decoded.payload, decoded.recordType, decoded.sequence, previousRecordDigest,
		)
		if err != nil {
			return ValidationSummary{}, err
		}
		if err := index.indexFrame(decoded, payload); err != nil {
			return ValidationSummary{}, err
		}
		previousRecordDigest = recordDigest
		offset += length
		expectedSequence++
	}
	if offset != len(contents) {
		return ValidationSummary{}, reject(ErrorCorrupt)
	}
	entries := make([]ValidationEntry, 0, len(index.entries))
	for _, started := range index.entries {
		entry := ValidationEntry{
			CapabilityID:     started.verified.Value().CapabilityID,
			CapabilityDigest: started.verified.Digest(),
			ArtifactDigest:   started.verified.Value().ArtifactDigest,
			StartedSequence:  started.sequence,
		}
		if started.terminal != nil {
			entry.Terminal = true
			entry.TerminalSequence = started.terminal.sequence
			entry.ResultDigest = started.terminal.verified.Digest()
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].StartedSequence < entries[right].StartedSequence
	})
	return ValidationSummary{Entries: entries, LastSequence: expectedSequence - 1}, nil
}
