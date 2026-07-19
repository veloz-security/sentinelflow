package tuning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

func digestJSON(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{'\n'})
	_, _ = digest.Write(encoded)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func digestStrings(domain string, values []string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{'\n'})
	for _, value := range values {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func integerText(value int) string { return strconv.Itoa(value) }
