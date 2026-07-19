package hil

import (
	"fmt"
	"strings"
	"testing"
)

func TestFormattingAndErrorsDoNotExposeSensitiveInputs(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
	reason := fixtureReason(OperationApprove)
	request := DecisionRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: reason,
	}
	decision, err := service.Consume(issued.Guard(), request)
	if err != nil {
		t.Fatal(err)
	}
	checkedReason, _ := CheckReason(reason)
	values := []any{
		service, NewDefaultService(), issued, issued.Guard(), issued.Guard().Record(),
		exact, checkedReason, decision, request,
		IssueRequest{Operation: OperationApprove, Session: session, Artifact: exact, IdempotencyKey: idempotency},
		reason,
	}
	for index, value := range values {
		formatted := fmt.Sprintf("%+v %#v", value, value)
		for _, forbidden := range []string{nonce, string(idempotency), reason.ReasonText, string(exact.CanonicalBytes())} {
			if strings.Contains(formatted, forbidden) {
				t.Fatalf("formatted value %d exposed sensitive input", index)
			}
		}
	}
	err = reject(ErrorNonce)
	if !IsCode(err, ErrorNonce) || IsCode(err, ErrorReason) ||
		strings.Contains(err.Error(), nonce) || strings.Contains(err.Error(), reason.ReasonText) {
		t.Fatalf("unsafe typed error: %v", err)
	}
}
