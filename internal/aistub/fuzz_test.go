package aistub

import (
	"context"
	"testing"
)

func FuzzAnalyzerNeverPanics(f *testing.F) {
	f.Add(validInputBytes(f))
	f.Add([]byte(`{"schema_version":"sentinelflow_analysis_input_v1"}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = New().Analyze(context.Background(), input)
	})
}
