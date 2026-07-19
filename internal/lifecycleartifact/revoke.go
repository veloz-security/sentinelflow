package lifecycleartifact

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

const (
	revokePrefix = "delete element inet sentinelflow blacklist_ipv4 { "
	revokeSuffix = " }\n"
)

// CheckRevokeArtifact creates the only supported nft-revoke-v1 mutation: one
// canonical IPv4 deletion from the owned inet sentinelflow blacklist_ipv4 set.
func CheckRevokeArtifact(targetIPv4 string) (CheckedRevokeArtifact, error) {
	if !validCanonicalIPv4(targetIPv4) {
		return CheckedRevokeArtifact{}, reject(ErrorArtifact)
	}
	canonical := revokePrefix + targetIPv4 + revokeSuffix
	if len(canonical) > MaxRevokeArtifactBytes {
		return CheckedRevokeArtifact{}, reject(ErrorArtifact)
	}
	return CheckedRevokeArtifact{
		value:     RevokeValue{SchemaVersion: RevokeSchemaVersion, TargetIPv4: targetIPv4},
		canonical: canonical,
		digest:    digestBytes([]byte(canonical)),
	}, nil
}

// ParseCanonicalRevokeArtifact rejects every alternate nftables surface,
// including additional statements, tables, sets, flags, shell text, comments,
// missing or extra newlines, and non-canonical IPv4 spelling.
func ParseCanonicalRevokeArtifact(data []byte) (CheckedRevokeArtifact, error) {
	if len(data) == 0 || len(data) > MaxRevokeArtifactBytes || !utf8.Valid(data) ||
		bytes.IndexByte(data, 0) >= 0 {
		return CheckedRevokeArtifact{}, reject(ErrorEncoding)
	}
	text := string(data)
	if !strings.HasPrefix(text, revokePrefix) || !strings.HasSuffix(text, revokeSuffix) {
		return CheckedRevokeArtifact{}, reject(ErrorArtifact)
	}
	target := strings.TrimSuffix(strings.TrimPrefix(text, revokePrefix), revokeSuffix)
	checked, err := CheckRevokeArtifact(target)
	if err != nil {
		return CheckedRevokeArtifact{}, err
	}
	if !bytes.Equal(data, checked.CanonicalBytes()) {
		return CheckedRevokeArtifact{}, reject(ErrorCanonical)
	}
	return checked, nil
}
