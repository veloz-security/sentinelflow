package hil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWireArtifactsMatchFrozenSchemaFieldSets(t *testing.T) {
	reason, err := CheckReason(fixtureReason(OperationApprove))
	if err != nil {
		t.Fatal(err)
	}
	clock := &mutableClock{now: testNow}
	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
	decision, err := service.Consume(issued.Guard(), DecisionRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove),
	})
	if err != nil {
		t.Fatal(err)
	}
	revokeChallenge, err := CheckChallenge(revokeChallengeFixture())
	if err != nil {
		t.Fatal(err)
	}
	revokeValue, _, _ := revokeDecisionFixture()
	revokeDecision, err := CheckDecision(revokeValue)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		schema   string
		artifact []byte
	}{
		{"reason", "hil_reason_v1.schema.json", reason.CanonicalBytes()},
		{"challenge", "hil_challenge_v1.schema.json", issued.Challenge().CanonicalBytes()},
		{"decision", "hil_decision_v1.schema.json", decision.CanonicalBytes()},
		{"revoke challenge", "hil_challenge_v1.schema.json", revokeChallenge.CanonicalBytes()},
		{"revoke decision", "hil_decision_v1.schema.json", revokeDecision.CanonicalBytes()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertSchemaFieldSet(t, test.schema, test.artifact)
		})
	}
}

func assertSchemaFieldSet(t *testing.T, filename string, artifact []byte) {
	t.Helper()
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "contracts", "enforcement", filename))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(artifact, &object); err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	propertyKeys := make([]string, 0, len(schema.Properties))
	for key := range schema.Properties {
		propertyKeys = append(propertyKeys, key)
	}
	artifactKeys := make([]string, 0, len(object))
	for key := range object {
		artifactKeys = append(artifactKeys, key)
	}
	slices.Sort(propertyKeys)
	slices.Sort(artifactKeys)
	slices.Sort(schema.Required)
	if !slices.Equal(propertyKeys, schema.Required) || !slices.Equal(propertyKeys, artifactKeys) {
		t.Fatalf("schema properties=%v required=%v artifact=%v", propertyKeys, schema.Required, artifactKeys)
	}
}
