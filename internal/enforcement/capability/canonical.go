package capability

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestEqual(left, right string) bool {
	if !digestPattern.MatchString(left) || !digestPattern.MatchString(right) {
		return false
	}
	leftBytes, leftErr := hex.DecodeString(left[len("sha256:"):])
	rightBytes, rightErr := hex.DecodeString(right[len("sha256:"):])
	if leftErr != nil || rightErr != nil {
		return false
	}
	return subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

func appendString(destination []byte, value string) []byte {
	encoded, _ := json.Marshal(value)
	return append(destination, encoded...)
}

func appendUint(destination []byte, value uint64) []byte {
	return strconv.AppendUint(destination, value, 10)
}

func appendNullableString(destination []byte, value string) []byte {
	if value == "" {
		return append(destination, "null"...)
	}
	return appendString(destination, value)
}

func appendNullableUint(destination []byte, value *uint64) []byte {
	if value == nil {
		return append(destination, "null"...)
	}
	return appendUint(destination, *value)
}

func strictDecode(data []byte, maximum int, destination any) error {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return reject(ErrorEncoding)
	}
	if err := rejectDuplicateNames(data); err != nil {
		return reject(ErrorEncoding)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return reject(ErrorEncoding)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return reject(ErrorEncoding)
	}
	return nil
}

func rejectDuplicateNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func scanJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}
