package hil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// appendJCSString implements the RFC 8785/ECMAScript string representation
// needed by this package. All artifact keys are fixed ASCII; this handles the
// one dynamic Unicode field (the NFC-normalized administrator reason) without
// encoding/json's HTML or U+2028/U+2029 escaping differences.
func appendJCSString(destination []byte, value string) []byte {
	const hex = "0123456789abcdef"
	destination = append(destination, '"')
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		switch r {
		case '"', '\\':
			destination = append(destination, '\\', byte(r))
		case '\b':
			destination = append(destination, `\b`...)
		case '\t':
			destination = append(destination, `\t`...)
		case '\n':
			destination = append(destination, `\n`...)
		case '\f':
			destination = append(destination, `\f`...)
		case '\r':
			destination = append(destination, `\r`...)
		default:
			if r < 0x20 {
				destination = append(destination, '\\', 'u', '0', '0', hex[byte(r)>>4], hex[byte(r)&0x0f])
			} else {
				destination = utf8.AppendRune(destination, r)
			}
		}
	}
	return append(destination, '"')
}

func appendUint32(destination []byte, value uint32) []byte {
	if value == 0 {
		return append(destination, '0')
	}
	var buffer [10]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return append(destination, buffer[index:]...)
}

func appendOptionalJCSString(destination []byte, value *string) []byte {
	if value == nil {
		return append(destination, "null"...)
	}
	return appendJCSString(destination, *value)
}

func rejectDuplicateJSONNames(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
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
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
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

func decodeStrict(data []byte, maximum int, destination any) error {
	if len(data) == 0 || len(data) > maximum || rejectDuplicateJSONNames(data) != nil {
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
