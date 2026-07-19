package validation

import (
	"context"
	"testing"
)

func FuzzDemoHistoryManifestVerifier(f *testing.F) {
	verifier := newFixtureDemoHistoryVerifier(f)
	fixture := readDemoHistoryFixture(f)
	f.Add(fixture, PinnedDemoHistoryImportedRowsDigest, PinnedDemoHistoryDatasetRecordCount)
	f.Add([]byte(`{}`), "sha256:0000000000000000000000000000000000000000000000000000000000000000", uint64(0))
	f.Add([]byte{0xff, 0xfe, 0xfd}, PinnedDemoHistoryImportedRowsDigest, PinnedDemoHistoryDatasetRecordCount)

	f.Fuzz(func(t *testing.T, envelope []byte, importedRowsDigest string, importedRecordCount uint64) {
		if len(envelope) > MaxDemoHistorySignedEnvelopeBytes+1 {
			envelope = envelope[:MaxDemoHistorySignedEnvelopeBytes+1]
		}
		binding, err := verifier.VerifyDemoHistory(context.Background(), DemoHistoryVerificationInput{
			SignedManifestEnvelope: envelope,
			ImportedRowsDigest:     importedRowsDigest,
			ImportedRecordCount:    importedRecordCount,
		})
		if err != nil {
			if binding.verified || !binding.HistoryCutoff().At().IsZero() {
				t.Fatalf("rejected fuzz input returned a sealed binding: %+v", binding)
			}
			return
		}
		if !binding.verified || binding.HistoryCutoff().At().IsZero() ||
			binding.datasetDigest != PinnedDemoHistoryDatasetDigest ||
			binding.importedRowsDigest != PinnedDemoHistoryImportedRowsDigest ||
			binding.impactSourceHealthDigest != testDemoImpactSourceHealthDigest {
			t.Fatalf("successful fuzz input violated sealed binding invariants: %+v", binding)
		}
	})
}
