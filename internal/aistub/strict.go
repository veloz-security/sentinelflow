package aistub

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"unicode/utf8"
)

var (
	errInvalidInput = errors.New("aistub: compact input rejected")
	integerPattern  = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

func decodeInput(data []byte) (compactInput, error) {
	if !utf8.Valid(data) || strictJSON(data) != nil {
		return compactInput{}, errInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result compactInput
	if err := decoder.Decode(&result); err != nil {
		return compactInput{}, errInvalidInput
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return compactInput{}, errInvalidInput
	}
	return result, nil
}

func strictJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') || consumeStrict(decoder, token) != nil {
		return errInvalidInput
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidInput
	}
	return nil
}

func consumeStrict(decoder *json.Decoder, token json.Token) error {
	switch value := token.(type) {
	case json.Number:
		if !integerPattern.MatchString(value.String()) {
			return errInvalidInput
		}
		return nil
	case string:
		if !validText(value) {
			return errInvalidInput
		}
		return nil
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return errInvalidInput
				}
				key, ok := keyToken.(string)
				if !ok || !validText(key) {
					return errInvalidInput
				}
				if _, duplicate := seen[key]; duplicate {
					return errInvalidInput
				}
				seen[key] = struct{}{}
				child, err := decoder.Token()
				if err != nil || consumeStrict(decoder, child) != nil {
					return errInvalidInput
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errInvalidInput
			}
		case '[':
			for decoder.More() {
				child, err := decoder.Token()
				if err != nil || consumeStrict(decoder, child) != nil {
					return errInvalidInput
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errInvalidInput
			}
		default:
			return errInvalidInput
		}
	}
	return nil
}
