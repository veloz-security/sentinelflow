package authsender

import (
	"strings"
	"testing"
)

func FuzzDecodeAcknowledgement(f *testing.F) {
	valid := []byte(`{"status":"accepted","sender_id":"auth-app","sender_epoch":"AQEBAQEBAQEBAQEBAQEBAQ","batch_id":"019b0000-0000-7000-8000-000000000001","sequence":1,"body_digest":"sha256:` + strings.Repeat("a", 64) + `"}`)
	f.Add(valid)
	f.Add([]byte(`{"status":"accepted","status":"duplicate"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, input []byte) {
		ack, err := decodeAcknowledgement(input)
		if err == nil {
			if ack.Status != "accepted" && ack.Status != "duplicate" {
				t.Fatalf("accepted status = %q", ack.Status)
			}
			if !senderPattern.MatchString(ack.SenderID) || !validEpoch(ack.SenderEpoch) ||
				!uuidPattern.MatchString(ack.BatchID) || !digestPattern.MatchString(ack.BodyDigest) || ack.Sequence < 1 {
				t.Fatalf("accepted invalid acknowledgement: %#v", ack)
			}
		}
	})
}

func FuzzStrictJSONObject(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a":[{"b":1}]}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_ = validateStrictJSONObject(input)
	})
}
