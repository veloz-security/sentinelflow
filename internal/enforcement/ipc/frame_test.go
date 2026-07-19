package ipc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type ipcVectorBundle struct {
	Vectors struct {
		Request  ipcFrameVector `json:"uds_request_frame_v1"`
		Response ipcFrameVector `json:"uds_response_frame_v1"`
	} `json:"vectors"`
}

type ipcFrameVector struct {
	PayloadLength   int    `json:"payload_length"`
	PayloadJCSB64   string `json:"payload_jcs_b64url"`
	FrameB64        string `json:"frame_b64url"`
	MaxPayloadBytes int    `json:"max_payload_bytes"`
}

func TestContractFrameVectors(t *testing.T) {
	t.Parallel()
	vectors := loadIPCVectors(t)
	for name, vector := range map[string]ipcFrameVector{
		"request":  vectors.Vectors.Request,
		"response": vectors.Vectors.Response,
	} {
		vector := vector
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			payload := decodeRawVector(t, vector.PayloadJCSB64)
			frame := decodeRawVector(t, vector.FrameB64)
			if len(payload) != vector.PayloadLength || vector.MaxPayloadBytes != MaxFramePayloadBytes {
				t.Fatal("frame vector metadata differs from runtime constants")
			}
			encoded, err := EncodeFrame(payload)
			if err != nil || !bytes.Equal(encoded, frame) {
				t.Fatalf("EncodeFrame() does not match vector: error=%v", err)
			}
			decoded, err := ReadSingleFrame(bytes.NewReader(frame))
			if err != nil || !bytes.Equal(decoded, payload) {
				t.Fatalf("ReadSingleFrame() = (%d bytes, %v)", len(decoded), err)
			}
		})
	}
}

func TestFrameBoundsAndTermination(t *testing.T) {
	t.Parallel()
	maxPayload := bytes.Repeat([]byte{'a'}, MaxFramePayloadBytes)
	maxFrame, err := EncodeFrame(maxPayload)
	if err != nil {
		t.Fatalf("EncodeFrame(max) error = %v", err)
	}
	if decoded, readErr := ReadSingleFrame(bytes.NewReader(maxFrame)); readErr != nil || !bytes.Equal(decoded, maxPayload) {
		t.Fatalf("max frame read error = %v", readErr)
	}

	oversizedHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(oversizedHeader, MaxFramePayloadBytes+1)
	valid, _ := EncodeFrame([]byte("{}"))
	for _, test := range []struct {
		name  string
		frame []byte
		want  error
	}{
		{"empty", nil, ErrFrameTruncated},
		{"short header", []byte{0, 0, 0}, ErrFrameTruncated},
		{"zero", []byte{0, 0, 0, 0}, ErrFrameZeroLength},
		{"oversized", oversizedHeader, ErrFrameOversized},
		{"short payload", []byte{0, 0, 0, 2, '{'}, ErrFrameTruncated},
		{"trailing byte", append(append([]byte(nil), valid...), 'x'), ErrFrameTrailingData},
		{"second frame", append(append([]byte(nil), valid...), valid...), ErrFrameTrailingData},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, got := ReadSingleFrame(bytes.NewReader(test.frame))
			if !errors.Is(got, test.want) {
				t.Fatalf("ReadSingleFrame() error = %v, want %v", got, test.want)
			}
		})
	}
	if _, err = EncodeFrame(nil); !errors.Is(err, ErrFrameZeroLength) {
		t.Fatalf("EncodeFrame(nil) error = %v", err)
	}
	if _, err = EncodeFrame(make([]byte, MaxFramePayloadBytes+1)); !errors.Is(err, ErrFrameOversized) {
		t.Fatalf("EncodeFrame(oversized) error = %v", err)
	}
}

type shortWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (w *shortWriter) Write(value []byte) (int, error) {
	if len(value) > w.limit {
		value = value[:w.limit]
	}
	return w.buffer.Write(value)
}

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"ok":true}`)
	writer := &shortWriter{limit: 2}
	if err := WriteFrame(writer, payload); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	want, _ := EncodeFrame(payload)
	if !bytes.Equal(writer.buffer.Bytes(), want) {
		t.Fatal("short writes changed the exact frame")
	}
}

func FuzzReadSingleFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, frame []byte) {
		payload, err := ReadSingleFrame(bytes.NewReader(frame))
		if err != nil {
			return
		}
		if len(payload) == 0 || len(payload) > MaxFramePayloadBytes {
			t.Fatal("accepted payload outside frame bounds")
		}
		reencoded, encodeErr := EncodeFrame(payload)
		if encodeErr != nil || !bytes.Equal(reencoded, frame) {
			t.Fatal("accepted frame was not one exact frame")
		}
	})
}

func loadIPCVectors(t *testing.T) ipcVectorBundle {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/vectors/contract_vectors_v1.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var bundle ipcVectorBundle
	if err = json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return bundle
}

func decodeRawVector(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("base64url decode error = %v", err)
	}
	return decoded
}
