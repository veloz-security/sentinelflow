package demohistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

const maxJSONDepth = 16

func validateStrictJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return reject(ErrorJSON)
	}
	if err := consumeStrictJSON(decoder, token, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return reject(ErrorJSON)
	}
	return nil
}

func consumeStrictJSON(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > maxJSONDepth {
		return reject(ErrorInputBounds)
	}
	if number, ok := token.(json.Number); ok {
		text := number.String()
		if strings.ContainsAny(text, ".eE") {
			return reject(ErrorContract)
		}
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value > eventsMaxSafeInteger || strconv.FormatUint(value, 10) != text {
			return reject(ErrorContract)
		}
		return nil
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
				return reject(ErrorJSON)
			}
			key, ok := keyToken.(string)
			if !ok {
				return reject(ErrorJSON)
			}
			if _, duplicate := seen[key]; duplicate {
				return reject(ErrorShape)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return reject(ErrorJSON)
			}
			if err := consumeStrictJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return reject(ErrorJSON)
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return reject(ErrorJSON)
			}
			if err := consumeStrictJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return reject(ErrorJSON)
		}
	default:
		return reject(ErrorJSON)
	}
	return nil
}

func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, reject(ErrorShape)
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, reject(ErrorJSON)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, reject(ErrorJSON)
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, reject(ErrorShape)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, reject(ErrorJSON)
		}
		fields[key] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, reject(ErrorJSON)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, reject(ErrorJSON)
	}
	return fields, nil
}

func requireFields(fields map[string]json.RawMessage, expected ...string) error {
	if len(fields) != len(expected) {
		return reject(ErrorShape)
	}
	for _, name := range expected {
		if _, ok := fields[name]; !ok {
			return reject(ErrorShape)
		}
	}
	return nil
}

func readString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", reject(ErrorShape)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", reject(ErrorContract)
	}
	return value, nil
}

func readUint(fields map[string]json.RawMessage, name string, minimum, maximum uint64) (uint64, error) {
	raw, ok := fields[name]
	if !ok {
		return 0, reject(ErrorShape)
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, reject(ErrorContract)
	}
	text := number.String()
	if strings.ContainsAny(text, ".eE") {
		return 0, reject(ErrorContract)
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, reject(ErrorContract)
	}
	return value, nil
}

func readRawArray(fields map[string]json.RawMessage, name string) ([]json.RawMessage, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, reject(ErrorShape)
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, reject(ErrorShape)
	}
	return values, nil
}

func canonicalJSON(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, reject(ErrorJSON)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, reject(ErrorJSON)
	}
	buffer := bytes.NewBuffer(make([]byte, 0, len(raw)))
	if err := appendCanonicalJSON(buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func appendCanonicalJSON(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return reject(ErrorEncoding)
		}
		buffer.Write(encoded)
	case json.Number:
		text := typed.String()
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value > eventsMaxSafeInteger || strconv.FormatUint(value, 10) != text {
			return reject(ErrorContract)
		}
		buffer.WriteString(text)
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := appendCanonicalJSON(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys) // All accepted contract keys are ASCII.
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return reject(ErrorEncoding)
			}
			buffer.Write(encoded)
			buffer.WriteByte(':')
			if err := appendCanonicalJSON(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return reject(ErrorContract)
	}
	return nil
}
