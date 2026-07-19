//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftbootstrap"
)

// TestProductionApplicationInExplicitlyIsolatedNamespace exercises the exact
// production startup path only when a deployment harness has placed the test
// process in a disposable network namespace with the executor's real mounts,
// keys, configuration, and NET_ADMIN boundary. It reports only the already
// redacted top-level runtime code.
func TestProductionApplicationInExplicitlyIsolatedNamespace(t *testing.T) {
	if os.Getenv("SENTINELFLOW_EXECUTOR_ISOLATED_NAMESPACE_TEST") != "acknowledged" {
		t.Skip("requires an explicitly acknowledged disposable network namespace")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	application, err := newProductionApplication(ctx)
	if err != nil {
		t.Fatalf(
			"production executor startup code = %q, schema boundary code = %q",
			runtimeCode(err), diagnoseSchemaBoundary(ctx),
		)
	}
	application.close()
}

func diagnoseSchemaBoundary(ctx context.Context) nftbootstrap.ErrorCode {
	configured, err := config.Load(config.RoleExecutor)
	if err != nil {
		return ""
	}
	baseContract, err := readBoundedBaseContract(configured.Enforcement.BaseChainContract)
	if err != nil {
		return ""
	}
	manager, err := nftbootstrap.NewProductionManager()
	if err != nil {
		return ""
	}
	_, err = manager.Bootstrap(ctx, baseContract)
	var rejected *nftbootstrap.Error
	if !errors.As(err, &rejected) {
		return ""
	}
	return rejected.Code
}
