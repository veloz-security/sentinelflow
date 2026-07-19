package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errInvalidJSON = errors.New("invalid strict JSON")

func validateJSONDocument(data []byte, requireObject bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return errInvalidJSON
	}
	if requireObject && token != json.Delim('{') {
		return errInvalidJSON
	}
	if err := consumeJSONValue(decoder, token); err != nil {
		return errInvalidJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidJSON
			}
			if _, duplicate := seen[key]; duplicate {
				return errInvalidJSON
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidJSON
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidJSON
		}
	default:
		return errInvalidJSON
	}
	return nil
}
