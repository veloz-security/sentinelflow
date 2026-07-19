package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftbinary"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidator"
	"golang.org/x/sys/unix"
)

func main() {
	os.Exit(run())
}

func run() int {
	_ = unix.Umask(0o077)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "SentinelFlow nft validator stopped")
		return 1
	}
	fmt.Fprintf(os.Stdout, "%s validator %s stopped\n", buildinfo.Name, buildinfo.Version)
	return 0
}

func serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("validator: context is required")
	}
	runtimeConfig, err := config.Load(config.RoleValidator)
	if err != nil {
		return errors.New("validator: configuration rejected")
	}
	baseContract, err := nftvalidator.LoadPinnedBaseContract(runtimeConfig.Enforcement.BaseChainContract)
	if err != nil {
		return errors.New("validator: base contract rejected")
	}
	runner, err := nftvalidator.NewProductionRunner(baseContract)
	if err != nil {
		return errors.New("validator: nft runner unavailable")
	}
	expectedDigest := "sha256:" + runtimeConfig.Enforcement.NFTBinaryExpectedSHA256
	attestation, err := nftbinary.Verify(ctx, runner, expectedDigest, runtimeConfig.Enforcement.NFTExpectedVersion)
	if err != nil {
		return errors.New("validator: nft binary attestation rejected")
	}
	checker, err := nftcheck.New(runner, attestation.Version)
	if err != nil {
		return errors.New("validator: checker configuration rejected")
	}
	service, err := nftvalidator.NewService(nftvalidator.ServiceConfig{
		Checker: checker, BaseContract: baseContract,
		NFTBinaryDigest: attestation.BinaryDigest, NFTVersion: attestation.Version,
	})
	if err != nil {
		return errors.New("validator: service configuration rejected")
	}
	server, err := nftvalidator.Listen(
		runtimeConfig.Enforcement.ValidatorSocket,
		nftvalidator.ExchangeTimeout,
		service,
	)
	if err != nil {
		return errors.New("validator: private socket rejected")
	}
	defer server.Close()
	fmt.Fprintf(os.Stdout, "%s validator %s ready\n", buildinfo.Name, buildinfo.Version)
	if err := server.Serve(ctx); err != nil {
		return errors.New("validator: private socket failed")
	}
	return nil
}
