package events

import (
	"encoding/json"
	"time"
)

// Timestamp is a validated UTC RFC 3339 timestamp. Wire input must use the Z
// designator; offsets such as +00:00 are rejected even when they denote UTC.
type Timestamp struct {
	value time.Time
	valid bool
}

// ParseTimestamp validates a UTC RFC 3339 timestamp using nanosecond precision.
func ParseTimestamp(value string) (Timestamp, error) {
	if len(value) == 0 || value[len(value)-1] != 'Z' {
		return Timestamp{}, fieldError("$", ErrorInvalidFormat, "must be a UTC RFC3339 timestamp using Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return Timestamp{}, fieldError("$", ErrorInvalidFormat, "must be a UTC RFC3339 timestamp using Z")
	}
	return Timestamp{value: parsed.UTC(), valid: true}, nil
}

// NewTimestamp creates a wire timestamp from a time whose numeric UTC offset
// is zero.
func NewTimestamp(value time.Time) (Timestamp, error) {
	_, offset := value.Zone()
	if offset != 0 {
		return Timestamp{}, fieldError("$", ErrorInvalidFormat, "must have a zero UTC offset")
	}
	return Timestamp{value: value.UTC(), valid: true}, nil
}

// Time returns the normalized UTC time. An invalid zero-value Timestamp
// returns time.Time's zero value.
func (t Timestamp) Time() time.Time {
	if !t.valid {
		return time.Time{}
	}
	return t.value
}

// Valid reports whether the timestamp was created through a validating
// constructor or decoder.
func (t Timestamp) Valid() bool {
	return t.valid
}

func (t Timestamp) String() string {
	if !t.valid {
		return ""
	}
	return t.value.UTC().Format(time.RFC3339Nano)
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	if !t.valid {
		return nil, fieldError("$", ErrorRequired, "timestamp is required")
	}
	return json.Marshal(t.String())
}

func (t *Timestamp) UnmarshalJSON(data []byte) error {
	value, err := decodeJSONString(data)
	if err != nil {
		return err
	}
	parsed, err := ParseTimestamp(value)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}
