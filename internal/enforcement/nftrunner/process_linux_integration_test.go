//go:build linux && integration

package nftrunner

import (
	"context"
	"testing"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

// TestProductionProcessAgainstDisposableOwnedSet requires an already-created
// empty owned set in a disposable Linux network namespace. It never creates a
// table, changes the host namespace, or accepts a caller-selected invocation.
func TestProductionProcessAgainstDisposableOwnedSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), MaxOperationDuration)
	defer cancel()

	mutation, runErr := runProductionProcess(ctx, processRequest{
		kind: processMutation, stdin: append([]byte(nil), testAddArtifact...),
	})
	if runErr || mutation.exitStatus != 0 || mutation.overflow || mutation.signaled {
		t.Fatalf("fixed mutation failed: exit=%d overflow=%t signaled=%t", mutation.exitStatus, mutation.overflow, mutation.signaled)
	}

	readback, runErr := runProductionProcess(ctx, processRequest{kind: processInspect})
	if runErr || readback.exitStatus != 0 || readback.overflow || readback.signaled || len(readback.stderr) != 0 {
		t.Fatalf("fixed readback failed: exit=%d overflow=%t signaled=%t", readback.exitStatus, readback.overflow, readback.signaled)
	}
	observation, err := parseReadback(readback.stdout, testTarget, nftvalidate.PinnedLiveSchemaDigest)
	if err != nil || observation.State != capability.ReadbackActive || observation.RemainingTTLSeconds == 0 ||
		observation.RemainingTTLSeconds > 1800 {
		t.Fatalf("projection failed: state=%s ttl=%d err=%v", observation.State, observation.RemainingTTLSeconds, err)
	}
}
