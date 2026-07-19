package demohistoryseal

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type publicAssertionVectorSet struct {
	ValidCases    []publicAssertionVectorCase `json:"valid_cases"`
	NegativeCases []publicAssertionVectorCase `json:"negative_cases"`
}

type publicAssertionVectorCase struct {
	CaseID               string                     `json:"case_id"`
	Payload              map[string]json.RawMessage `json:"payload"`
	ExpectedSchemaValid  bool                       `json:"expected_schema_valid"`
	ExpectedBindingValid bool                       `json:"expected_binding_valid"`
}

var publicAssertionFields = []string{
	"clock_at",
	"impact_source_health_digest",
	"import_id",
	"issued_at",
	"manifest_digest",
	"manifest_id",
	"public_key_b64url",
	"run_scope",
	"schema_version",
	"signature_verification_digest",
}

func TestDemoHistoryPublicAssertionContractVectors(t *testing.T) {
	vectors := readPublicAssertionContractVectors(t)
	if len(vectors.ValidCases) == 0 || len(vectors.NegativeCases) == 0 {
		t.Fatal("demo-history public assertion vectors are empty")
	}

	rawDataset := fixtureDataset(t)
	bundle, err := Seal(context.Background(), rawDataset, bytes.NewReader(randomMaterial(61)))
	if err != nil {
		t.Fatal(err)
	}
	runtimePayload := decodeAssertionObject(t, bundle.PublicAssertions())
	assertExactAssertionFields(t, runtimePayload)
	if _, _, err = VerifyBundle(
		context.Background(), rawDataset, bundle.SignedEnvelope(), bundle.PublicAssertions(),
	); err != nil {
		t.Fatalf("fresh run-scoped bundle did not verify: %v", err)
	}

	validBaseline := vectors.ValidCases[0].Payload
	for _, vector := range vectors.ValidCases {
		t.Run("valid/"+vector.CaseID, func(t *testing.T) {
			if !vector.ExpectedSchemaValid || !vector.ExpectedBindingValid {
				t.Fatalf("valid vector has false expectation: %+v", vector)
			}
			assertExactAssertionFields(t, vector.Payload)
			raw := marshalAssertionObject(t, vector.Payload)
			if _, err := ParseAssertions(raw); err != nil {
				t.Fatalf("public assertion vector did not parse: %v", err)
			}

			// Golden vectors contain public test identities only and intentionally
			// omit the matching private material/envelope. They must never bind to
			// a freshly sealed runtime authority merely because their shape is valid.
			if _, _, err := VerifyBundle(
				context.Background(), rawDataset, bundle.SignedEnvelope(), raw,
			); err == nil {
				t.Fatal("public test identity bound to an unrelated runtime envelope")
			}
		})
	}

	for _, vector := range vectors.NegativeCases {
		t.Run("negative/"+vector.CaseID, func(t *testing.T) {
			if vector.ExpectedBindingValid {
				t.Fatalf("negative vector unexpectedly claims valid binding: %+v", vector)
			}
			raw := marshalAssertionObject(t, vector.Payload)
			_, parseErr := ParseAssertions(raw)
			switch {
			case !vector.ExpectedSchemaValid && parseErr == nil:
				t.Fatal("schema-invalid public assertion parsed")
			case vector.CaseID == "issued-before-clock" && parseErr == nil:
				t.Fatal("issued_at before clock_at passed the stricter cross-field safety rule")
			case vector.ExpectedSchemaValid && vector.CaseID != "issued-before-clock" && parseErr != nil:
				t.Fatalf("schema-valid binding-negative assertion failed local parsing: %v", parseErr)
			}

			candidate := applyAssertionVectorDelta(runtimePayload, validBaseline, vector.Payload)
			candidateRaw := marshalAssertionObject(t, candidate)
			if _, _, err := VerifyBundle(
				context.Background(), rawDataset, bundle.SignedEnvelope(), candidateRaw,
			); err == nil {
				t.Fatal("negative vector mutation retained runtime authority")
			}
		})
	}
}

func TestDemoHistoryPublicAssertionsRejectAuthorityFields(t *testing.T) {
	vectors := readPublicAssertionContractVectors(t)
	if len(vectors.ValidCases) == 0 {
		t.Fatal("demo-history public assertion valid vector is missing")
	}
	for _, field := range []string{
		"private_key_b64url",
		"signature_b64url",
		"signed_envelope",
		"raw_dataset",
		"database_worker_url",
		"executor_signing_key",
	} {
		t.Run(field, func(t *testing.T) {
			candidate := cloneAssertionObject(vectors.ValidCases[0].Payload)
			candidate[field] = json.RawMessage(`"forbidden"`)
			if _, err := ParseAssertions(marshalAssertionObject(t, candidate)); err == nil {
				t.Fatalf("authority field %q was accepted", field)
			}
		})
	}
}

func readPublicAssertionContractVectors(t testing.TB) publicAssertionVectorSet {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "vectors", "contract_vectors_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var projection struct {
		Vectors map[string]json.RawMessage `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &projection); err != nil {
		t.Fatal(err)
	}
	selected, ok := projection.Vectors["demo_history_public_assertions_v1"]
	if !ok {
		t.Fatal("demo-history public assertion vector set is missing")
	}
	var result publicAssertionVectorSet
	if err = json.Unmarshal(selected, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeAssertionObject(t testing.TB, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func marshalAssertionObject(t testing.TB, object map[string]json.RawMessage) []byte {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertExactAssertionFields(t testing.TB, object map[string]json.RawMessage) {
	t.Helper()
	got := make([]string, 0, len(object))
	for field := range object {
		got = append(got, field)
	}
	sort.Strings(got)
	want := append([]string(nil), publicAssertionFields...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("public assertion fields=%v want=%v", got, want)
	}
}

func applyAssertionVectorDelta(
	runtime, baseline, negative map[string]json.RawMessage,
) map[string]json.RawMessage {
	result := cloneAssertionObject(runtime)
	for field, baselineValue := range baseline {
		negativeValue, present := negative[field]
		if !present {
			delete(result, field)
			continue
		}
		if !bytes.Equal(baselineValue, negativeValue) {
			result[field] = bytes.Clone(negativeValue)
		}
	}
	for field, negativeValue := range negative {
		if _, present := baseline[field]; !present {
			result[field] = bytes.Clone(negativeValue)
		}
	}
	return result
}

func cloneAssertionObject(source map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(source))
	for field, value := range source {
		result[field] = bytes.Clone(value)
	}
	return result
}
