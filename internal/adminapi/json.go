package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/adminauth"
)

var errInvalidRequest = errors.New("administrator request is invalid")

type loginInput struct {
	username string
	password []byte
}

type stepUpInput struct {
	password []byte
}

func readStrictBody(request *http.Request) ([]byte, error) {
	return readStrictBodyWithLimit(request, MaxRequestBodyBytes)
}

func readStrictBodyWithLimit(request *http.Request, maximum int64) ([]byte, error) {
	if request == nil || request.Body == nil || maximum < 1 || request.ContentLength > maximum ||
		request.ContentLength < -1 || len(request.TransferEncoding) > 1 ||
		len(request.TransferEncoding) == 1 && request.TransferEncoding[0] != "chunked" {
		return nil, errInvalidRequest
	}
	reader := io.LimitReader(request.Body, maximum+1)
	body, err := io.ReadAll(reader)
	if err != nil || int64(len(body)) > maximum || len(body) == 0 || !utf8.Valid(body) {
		clear(body)
		return nil, errInvalidRequest
	}
	return body, nil
}

func decodeLogin(request *http.Request) (loginInput, error) {
	body, err := readStrictBody(request)
	if err != nil {
		return loginInput{}, err
	}
	defer clear(body)
	result := loginInput{}
	err = decodeObject(body, map[string]func(*json.Decoder) error{
		"username": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, 128)
			if decodeErr == nil {
				result.username = string(value)
			}
			clear(value)
			return decodeErr
		},
		"password": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, adminPasswordLimit())
			if decodeErr == nil {
				result.password = value
			}
			return decodeErr
		},
	})
	if err != nil || result.username == "" || len(result.password) == 0 {
		clear(result.password)
		return loginInput{}, errInvalidRequest
	}
	return result, nil
}

func decodeStepUp(request *http.Request) (stepUpInput, error) {
	body, err := readStrictBody(request)
	if err != nil {
		return stepUpInput{}, err
	}
	defer clear(body)
	result := stepUpInput{}
	err = decodeObject(body, map[string]func(*json.Decoder) error{
		"password": func(decoder *json.Decoder) error {
			value, decodeErr := decodeString(decoder, adminPasswordLimit())
			if decodeErr == nil {
				result.password = value
			}
			return decodeErr
		},
	})
	if err != nil || len(result.password) == 0 {
		clear(result.password)
		return stepUpInput{}, errInvalidRequest
	}
	return result, nil
}

func decodeEmptyObject(request *http.Request) error {
	body, err := readStrictBody(request)
	if err != nil {
		return err
	}
	defer clear(body)
	return decodeObject(body, map[string]func(*json.Decoder) error{})
}

func decodeObject(body []byte, fields map[string]func(*json.Decoder) error) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errInvalidRequest
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errInvalidRequest
		}
		name, ok := token.(string)
		decode, known := fields[name]
		if !ok || !known {
			return errInvalidRequest
		}
		if _, duplicate := seen[name]; duplicate {
			return errInvalidRequest
		}
		seen[name] = struct{}{}
		if err := decode(decoder); err != nil {
			return errInvalidRequest
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(fields) {
		return errInvalidRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func decodeString(decoder *json.Decoder, maximum int) ([]byte, error) {
	var value string
	if decoder.Decode(&value) != nil || len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) {
		return nil, errInvalidRequest
	}
	return []byte(value), nil
}

func adminPasswordLimit() int {
	// The boundary converts every over-limit password to one generic Argon2
	// work input. The HTTP contract rejects it before hashing and clears bytes.
	return adminauth.MaxPasswordBytes
}

func validPOSTEnvelope(request *http.Request) bool {
	return validPOSTEnvelopeWithLimit(request, MaxRequestBodyBytes)
}

func validPOSTEnvelopeWithLimit(request *http.Request, maximum int64) bool {
	return request != nil && request.Method == http.MethodPost &&
		len(request.Header.Values("Content-Type")) == 1 && request.Header.Get("Content-Type") == "application/json" &&
		len(request.Header.Values("Content-Encoding")) == 0 && request.URL != nil && request.URL.RawQuery == "" &&
		!request.URL.ForceQuery && maximum > 0 && request.ContentLength >= 0 && request.ContentLength <= maximum &&
		len(request.TransferEncoding) == 0
}

func validGETEnvelope(request *http.Request) bool {
	if request == nil || request.Method != http.MethodGet || request.URL == nil || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		len(request.Header.Values("Content-Type")) != 0 || len(request.Header.Values("Content-Encoding")) != 0 ||
		request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	one := make([]byte, 1)
	count, err := request.Body.Read(one)
	clear(one)
	return count == 0 && errors.Is(err, io.EOF)
}
