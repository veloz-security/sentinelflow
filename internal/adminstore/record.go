package adminstore

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
)

const maximumActorIDBytes = 128

func cloneRecord(record adminauth.SessionRecord) adminauth.SessionRecord {
	clone := record
	clone.AuthenticatedAt = record.AuthenticatedAt.UTC()
	clone.CreatedAt = record.CreatedAt.UTC()
	clone.LastSeenAt = record.LastSeenAt.UTC()
	clone.ExpiresAt = record.ExpiresAt.UTC()
	if record.RevokedAt != nil {
		value := record.RevokedAt.UTC()
		clone.RevokedAt = &value
	}
	if record.RotationParentID != nil {
		value := *record.RotationParentID
		clone.RotationParentID = &value
	}
	return clone
}

func validRecord(record adminauth.SessionRecord) bool {
	record = cloneRecord(record)
	if !validUUIDv4(record.ID) || !validActorID(record.ActorID) ||
		zeroDigest(record.TokenDigest) || zeroDigest(record.CSRFDigest) ||
		record.TokenDigest == record.CSRFDigest ||
		!validTimestamp(record.AuthenticatedAt) || !validTimestamp(record.CreatedAt) ||
		!validTimestamp(record.LastSeenAt) || !validTimestamp(record.ExpiresAt) ||
		record.AuthenticatedAt.After(record.CreatedAt) || record.CreatedAt.After(record.LastSeenAt) ||
		!record.LastSeenAt.Before(record.ExpiresAt) || !record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.After(record.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)) {
		return false
	}
	if record.RevokedAt != nil && (!validTimestamp(*record.RevokedAt) || record.RevokedAt.Before(record.CreatedAt)) {
		return false
	}
	if record.RotationParentID != nil &&
		(!validUUIDv4(*record.RotationParentID) || *record.RotationParentID == record.ID) {
		return false
	}
	return true
}

func validLogin(record adminauth.SessionRecord, databaseNow time.Time) bool {
	return validRecord(record) && record.RevokedAt == nil && record.RotationParentID == nil &&
		record.AuthenticatedAt.Equal(record.CreatedAt) && record.CreatedAt.Equal(record.LastSeenAt) &&
		record.ExpiresAt.Equal(record.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)) &&
		activeAt(record, databaseNow)
}

func validReplacement(old, replacement adminauth.SessionRecord, databaseNow time.Time) bool {
	if !validRecord(replacement) || replacement.RevokedAt != nil || replacement.RotationParentID == nil ||
		*replacement.RotationParentID != old.ID || replacement.ActorID != old.ActorID ||
		replacement.ID == old.ID || replacement.TokenDigest == old.TokenDigest ||
		replacement.CSRFDigest == old.CSRFDigest ||
		!replacement.CreatedAt.Equal(replacement.LastSeenAt) ||
		!replacement.ExpiresAt.Equal(replacement.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)) ||
		replacement.CreatedAt.Before(old.LastSeenAt) || !activeAt(replacement, databaseNow) {
		return false
	}
	// A normal privileged rotation preserves the independent authentication
	// time. A password step-up sets it exactly to the new session creation time.
	return replacement.AuthenticatedAt.Equal(old.AuthenticatedAt) ||
		replacement.AuthenticatedAt.Equal(replacement.CreatedAt)
}

func activeAt(record adminauth.SessionRecord, databaseNow time.Time) bool {
	databaseNow = databaseNow.UTC()
	return validRecord(record) && record.RevokedAt == nil &&
		!databaseNow.Before(record.AuthenticatedAt) && !databaseNow.Before(record.CreatedAt) &&
		!databaseNow.Before(record.LastSeenAt) && databaseNow.Before(record.ExpiresAt) &&
		databaseNow.Before(record.LastSeenAt.Add(adminauth.SessionIdleLifetime))
}

func exactRecord(left, right adminauth.SessionRecord) bool {
	left = cloneRecord(left)
	right = cloneRecord(right)
	return left.ID == right.ID && left.ActorID == right.ActorID &&
		left.TokenDigest == right.TokenDigest && left.CSRFDigest == right.CSRFDigest &&
		left.AuthenticatedAt.Equal(right.AuthenticatedAt) && left.CreatedAt.Equal(right.CreatedAt) &&
		left.LastSeenAt.Equal(right.LastSeenAt) && left.ExpiresAt.Equal(right.ExpiresAt) &&
		equalOptionalTime(left.RevokedAt, right.RevokedAt) &&
		equalOptionalID(left.RotationParentID, right.RotationParentID)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func equalOptionalID(left, right *adminauth.SessionID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validActorID(value string) bool {
	if len(value) < 1 || len(value) > maximumActorIDBytes {
		return false
	}
	for index, char := range []byte(value) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
			index > 0 && (char == '.' || char == '_' || char == '-') {
			continue
		}
		return false
	}
	return true
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 &&
		value.Nanosecond()%int(time.Microsecond) == 0
}

func validDatabaseTime(value time.Time) bool {
	return validTimestamp(value)
}

func zeroDigest(value adminauth.Digest) bool {
	var zero adminauth.Digest
	return value == zero
}

func parseDigest(value string) (adminauth.Digest, bool) {
	var digest adminauth.Digest
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return digest, false
	}
	raw, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != value[len("sha256:"):] {
		return digest, false
	}
	copy(digest[:], raw)
	return digest, !zeroDigest(digest)
}

func parseSessionID(value string) (adminauth.SessionID, bool) {
	id, err := adminauth.ParseSessionID(value)
	return id, err == nil
}

func validUUIDv4(id adminauth.SessionID) bool {
	return !id.IsZero() && id[6]>>4 == 4 && id[8]>>6 == 2
}

func optionalIDString(id *adminauth.SessionID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

func optionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}
