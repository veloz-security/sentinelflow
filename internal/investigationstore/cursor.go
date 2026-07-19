package investigationstore

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

const (
	tupleCursorBytes = 24
	auditCursorBytes = 8
)

var strictRawURLBase64 = base64.RawURLEncoding.Strict()

type IncidentCursor struct {
	time time.Time
	id   string
	set  bool
}

type EventCursor struct {
	time time.Time
	id   string
	set  bool
}

type AuditCursor struct {
	sequence int64
	set      bool
}

func ParseIncidentCursor(value string) (IncidentCursor, error) {
	timestamp, id, err := parseTupleCursor(value, "i1.")
	if err != nil {
		return IncidentCursor{}, err
	}
	return IncidentCursor{time: timestamp, id: id, set: true}, nil
}

func ParseEventCursor(value string) (EventCursor, error) {
	timestamp, id, err := parseTupleCursor(value, "e1.")
	if err != nil {
		return EventCursor{}, err
	}
	return EventCursor{time: timestamp, id: id, set: true}, nil
}

func ParseAuditCursor(value string) (AuditCursor, error) {
	if !strings.HasPrefix(value, "a1.") {
		return AuditCursor{}, ErrInvalidArgument
	}
	payload, err := strictRawURLBase64.DecodeString(strings.TrimPrefix(value, "a1."))
	if err != nil || len(payload) != auditCursorBytes {
		return AuditCursor{}, ErrInvalidArgument
	}
	sequence := binary.BigEndian.Uint64(payload)
	if sequence == 0 || sequence > uint64(^uint64(0)>>1) {
		return AuditCursor{}, ErrInvalidArgument
	}
	return AuditCursor{sequence: int64(sequence), set: true}, nil
}

func (cursor IncidentCursor) String() string {
	if !cursor.set {
		return ""
	}
	return encodeTupleCursor("i1.", cursor.time, cursor.id)
}

func (cursor EventCursor) String() string {
	if !cursor.set {
		return ""
	}
	return encodeTupleCursor("e1.", cursor.time, cursor.id)
}

func (cursor AuditCursor) String() string {
	if !cursor.set || cursor.sequence <= 0 {
		return ""
	}
	payload := make([]byte, auditCursorBytes)
	binary.BigEndian.PutUint64(payload, uint64(cursor.sequence))
	return "a1." + base64.RawURLEncoding.EncodeToString(payload)
}

func newIncidentCursor(timestamp time.Time, id string) IncidentCursor {
	return IncidentCursor{time: timestamp.UTC(), id: id, set: true}
}

func newEventCursor(timestamp time.Time, id string) EventCursor {
	return EventCursor{time: timestamp.UTC(), id: id, set: true}
}

func newAuditCursor(sequence int64) AuditCursor {
	return AuditCursor{sequence: sequence, set: true}
}

func parseTupleCursor(value, prefix string) (time.Time, string, error) {
	if !strings.HasPrefix(value, prefix) {
		return time.Time{}, "", ErrInvalidArgument
	}
	payload, err := strictRawURLBase64.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(payload) != tupleCursorBytes {
		return time.Time{}, "", ErrInvalidArgument
	}
	microseconds := int64(binary.BigEndian.Uint64(payload[:8]))
	if microseconds <= 0 {
		return time.Time{}, "", ErrInvalidArgument
	}
	id := formatUUID(payload[8:])
	if !validUUID(id) {
		return time.Time{}, "", ErrInvalidArgument
	}
	return time.UnixMicro(microseconds).UTC(), id, nil
}

func encodeTupleCursor(prefix string, timestamp time.Time, id string) string {
	bytes, ok := parseUUIDBytes(id)
	if !ok || timestamp.IsZero() {
		return ""
	}
	payload := make([]byte, tupleCursorBytes)
	binary.BigEndian.PutUint64(payload[:8], uint64(timestamp.UTC().UnixMicro()))
	copy(payload[8:], bytes)
	return prefix + base64.RawURLEncoding.EncodeToString(payload)
}

func parseUUIDBytes(value string) ([]byte, bool) {
	if !validUUID(value) {
		return nil, false
	}
	raw := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(raw)
	return decoded, err == nil && len(decoded) == 16
}

func formatUUID(value []byte) string {
	if len(value) != 16 {
		return ""
	}
	raw := hex.EncodeToString(value)
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}
