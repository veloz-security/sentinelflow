package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/eventsender"
	"github.com/devwooops/sentinelflow/internal/gateway"
	"github.com/devwooops/sentinelflow/internal/observability"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow gateway failed:", err)
		os.Exit(1)
	}
}

func run() error {
	runtimeConfig, err := config.Load(config.RoleGateway)
	if err != nil {
		return err
	}
	hmacKey, err := decodeKey(runtimeConfig.Events.GatewayHMACKey.Reveal())
	if err != nil {
		return err
	}
	metrics := observability.New(observability.Config{})
	sender, err := eventsender.New(eventsender.Config{
		SenderID:       runtimeConfig.Events.GatewaySenderID,
		EndpointURL:    runtimeConfig.Events.GatewayIngestURL.String(),
		HMACKey:        hmacKey,
		CheckpointFile: runtimeConfig.Gateway.SenderCheckpointFile,
		QueueCapacity:  runtimeConfig.Gateway.EventQueueCapacity,
		BatchSize:      runtimeConfig.Gateway.EventBatchSize,
		MaxBatchBytes:  runtimeConfig.Gateway.EventMaxBatchBytes,
		FlushInterval:  runtimeConfig.Gateway.EventFlushInterval,
		Metrics:        metrics,
	})
	if err != nil {
		return err
	}
	closeSender := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return sender.Close(ctx)
	}

	handler, err := gateway.New(gateway.ConfigFromRuntime(runtimeConfig.Gateway), gateway.Dependencies{Sink: sender, Metrics: metrics})
	if err != nil {
		_ = closeSender()
		return err
	}
	server := gateway.NewHTTPServer(
		runtimeConfig.Gateway.ListenAddr,
		handler,
		runtimeConfig.Gateway.MaxHeaderBytes,
		runtimeConfig.Gateway.HeaderReadTimeout,
		runtimeConfig.Gateway.IdleTimeout,
	)
	server.ConnState = metrics.ObserveConnectionState
	metricsServer := newMetricsServer(runtimeConfig.Gateway.MetricsListenAddr, metrics.Handler())

	type listenerResult struct {
		name string
		err  error
	}
	serverErrors := make(chan listenerResult, 2)
	go func() {
		var serveErr error
		if runtimeConfig.Gateway.TLSCertFile != "" {
			serveErr = server.ListenAndServeTLS(runtimeConfig.Gateway.TLSCertFile, runtimeConfig.Gateway.TLSKeyFile)
		} else {
			serveErr = server.ListenAndServe()
		}
		serverErrors <- listenerResult{name: "public", err: serveErr}
	}()
	go func() {
		serverErrors <- listenerResult{name: "metrics", err: metricsServer.ListenAndServe()}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	var listenerFailure *listenerResult
	select {
	case result := <-serverErrors:
		listenerFailure = &result
	case <-signals:
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	publicShutdownErr := server.Shutdown(shutdownContext)
	metricsShutdownErr := metricsServer.Shutdown(shutdownContext)
	cancel()
	if publicShutdownErr != nil {
		_ = server.Close()
	}
	if metricsShutdownErr != nil {
		_ = metricsServer.Close()
	}
	senderErr := closeSender()
	if listenerFailure != nil && !errors.Is(listenerFailure.err, http.ErrServerClosed) {
		return errors.New(listenerFailure.name + " HTTP listener stopped unexpectedly")
	}
	if listenerFailure != nil {
		return errors.New(listenerFailure.name + " HTTP listener closed unexpectedly")
	}
	if publicShutdownErr != nil || metricsShutdownErr != nil {
		return errors.New("HTTP shutdown did not complete cleanly")
	}
	if senderErr != nil {
		return senderErr
	}
	return nil
}

func newMetricsServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4096,
	}
}

func decodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(value)
	}
	if err != nil || len(decoded) < 32 {
		return nil, errors.New("gateway event HMAC key is invalid")
	}
	return decoded, nil
}
