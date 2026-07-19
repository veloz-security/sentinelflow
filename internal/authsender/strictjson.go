package authsender

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func validateStrictJSONObject(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("authsender: invalid JSON object")
	}
	if err := consumeJSONValue(decoder, first); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("authsender: trailing JSON")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token) error {
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
				return errors.New("authsender: invalid JSON")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("authsender: invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("authsender: duplicate JSON object key")
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return errors.New("authsender: invalid JSON")
			}
			if err := consumeJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("authsender: invalid JSON object")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return errors.New("authsender: invalid JSON")
			}
			if err := consumeJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("authsender: invalid JSON array")
		}
	default:
		return errors.New("authsender: invalid JSON delimiter")
	}
	return nil
}
