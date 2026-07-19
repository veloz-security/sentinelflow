package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/devwooops/sentinelflow/internal/authsender"
	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/demoapp"
)

const (
	demoShutdownTimeout = 5 * time.Second
	demoMaxHeaderBytes  = 32 * 1024
	minimumKeyBytes     = 32
	maximumKeyBytes     = 4096
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("demo application stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	if ctx == nil || logger == nil {
		return errors.New("demo application: runtime dependencies are required")
	}
	runtimeConfig, err := config.Load(config.RoleDemoApp)
	if err != nil {
		return fmt.Errorf("load demo application configuration: %w", err)
	}

	authKey, err := decodeDemoKey(runtimeConfig.Events.AuthHMACKey.Reveal(), maximumKeyBytes)
	if err != nil {
		return errors.New("demo application: invalid auth event key")
	}
	defer clear(authKey)
	accountKey, err := decodeDemoKey(runtimeConfig.Events.AuthAccountHashKey.Reveal(), 128)
	if err != nil {
		return errors.New("demo application: invalid account hash key")
	}
	defer clear(accountKey)

	sender, err := authsender.New(authsender.Config{
		SenderID:       runtimeConfig.Events.AuthSenderID,
		EndpointURL:    runtimeConfig.Events.AuthIngestURL.String(),
		HMACKey:        authKey,
		CheckpointFile: runtimeConfig.Events.AuthCheckpointFile,
	})
	if err != nil {
		return errors.New("demo application: configure auth event sender")
	}
	closeSender := func() error {
		closeCtx, cancel := context.WithTimeout(context.Background(), demoShutdownTimeout)
		defer cancel()
		return sender.Close(closeCtx)
	}

	handler, err := demoapp.New(demoapp.Config{
		GatewayPeerCIDRs: runtimeConfig.Demo.GatewayPeerCIDRs,
		AccountHashKey:   accountKey,
		Sink:             sender,
	})
	if err != nil {
		_ = closeSender()
		return errors.New("demo application: configure private origin")
	}
	server := newDemoServer(runtimeConfig.Listeners.DemoOriginHTTPAddr, handler, logger)
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		_ = closeSender()
		return errors.New("demo application: bind private origin listener")
	}

	logger.Info("demo application configured", "service", buildinfo.Name, "version", buildinfo.Version)
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(listener) }()

	var serveErr error
	select {
	case <-ctx.Done():
	case err := <-serverResult:
		if err == nil || !errors.Is(err, http.ErrServerClosed) {
			serveErr = errors.New("demo application: private origin listener stopped unexpectedly")
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), demoShutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		_ = server.Close()
		if serveErr == nil {
			serveErr = errors.New("demo application: HTTP shutdown failed")
		}
	}
	if err := closeSender(); err != nil && serveErr == nil {
		serveErr = errors.New("demo application: auth event sender shutdown failed")
	}
	return serveErr
}

func newDemoServer(address string, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    demoMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}

func decodeDemoKey(encoded string, maximum int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(decoded) < minimumKeyBytes || len(decoded) > maximum {
		clear(decoded)
		return nil, errors.New("invalid encoded key")
	}
	return decoded, nil
}
