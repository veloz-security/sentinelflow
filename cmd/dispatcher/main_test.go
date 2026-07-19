package main

import (
	"context"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

func TestValidateRuntimeConfigPinsIPCContract(t *testing.T) {
	valid := config.Config{Role: config.RoleDispatcher}
	valid.Enforcement.ExecutorMaxFrameBytes = ipc.MaxFramePayloadBytes
	valid.Enforcement.ExecutorIOTimeout = ipc.MaxExchangeTimeout
	valid.Enforcement.DispatchCapabilityTTL = time.Minute
	if err := validateRuntimeConfig(valid); err != nil {
		t.Fatalf("valid config error=%v", err)
	}
	for name, mutate := range map[string]func(*config.Config){
		"role":    func(value *config.Config) { value.Role = config.RoleWorker },
		"frame":   func(value *config.Config) { value.Enforcement.ExecutorMaxFrameBytes-- },
		"timeout": func(value *config.Config) { value.Enforcement.ExecutorIOTimeout = time.Second },
		"ttl":     func(value *config.Config) { value.Enforcement.DispatchCapabilityTTL = time.Minute + time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateRuntimeConfig(candidate); err == nil {
				t.Fatal("invalid dispatcher contract was accepted")
			}
		})
	}
}

func TestRunRejectsMissingDependencies(t *testing.T) {
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("nil logger accepted")
	}
}
