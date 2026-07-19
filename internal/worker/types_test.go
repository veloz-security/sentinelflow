package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRegistryRejectsReservedUnknownAndNilHandlers(t *testing.T) {
	t.Parallel()

	valid := HandlerFunc(func(context.Context, Job) error { return nil })
	for name, handlers := range map[string]map[JobKind]Handler{
		"dispatch": {JobDispatchAdd: valid},
		"unknown":  {JobKind("future_job"): valid},
		"nil":      {JobDetect: nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRegistry(handlers); err == nil {
				t.Fatal("invalid handler registry was accepted")
			}
		})
	}
}

func TestRunnerConstructionRejectsUnsafeLeaseConfiguration(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	config := DefaultConfig("worker-test")
	config.LeaseDuration = MaxLeaseDuration + time.Nanosecond
	if _, err := NewRunner(store, registry, config, Dependencies{}); err == nil {
		t.Fatal("lease over 60 seconds was accepted")
	}
}

func TestHandlerFailureStringOmitsCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("sensitive-payload-value")
	failure := RetryableFailure("temporary_failure", cause)
	if strings.Contains(failure.Error(), cause.Error()) {
		t.Fatal("failure string exposed its cause")
	}
	if !errors.Is(failure, cause) {
		t.Fatal("failure did not preserve programmatic cause matching")
	}
}
