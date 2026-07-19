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
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/api"
	"github.com/devwooops/sentinelflow/internal/authbinding"
	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/ingestion"
	"github.com/devwooops/sentinelflow/internal/repository"
)

const (
	shutdownTimeout      = 10 * time.Second
	authBindingInterval  = 100 * time.Millisecond
	authBindingBatchSize = 100
)

type serverResult struct {
	name string
	err  error
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("api stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	if ctx == nil || logger == nil {
		return errors.New("api: runtime dependencies are required")
	}
	cfg, err := config.Load(config.RoleAPI)
	if err != nil {
		return fmt.Errorf("load api configuration: %w", err)
	}
	logger.Info("api configured", "service", buildinfo.Name, "version", buildinfo.Version)

	gatewayKey, err := decodeHMACKey(cfg.Events.GatewayHMACKey)
	if err != nil {
		return err
	}
	authKey, err := decodeHMACKey(cfg.Events.AuthHMACKey)
	if err != nil {
		return err
	}
	registry, err := ingestion.NewRegistry([]ingestion.Binding{
		{
			SenderID:     cfg.Events.GatewaySenderID,
			EndpointPath: ingestion.GatewayEventsPath,
			KeyID:        cfg.Events.GatewayHMACKeyID,
			Key:          gatewayKey,
		},
		{
			SenderID:     cfg.Events.AuthSenderID,
			EndpointPath: ingestion.AuthEventsPath,
			KeyID:        cfg.Events.AuthHMACKeyID,
			Key:          authKey,
		},
	})
	clear(gatewayKey)
	clear(authKey)
	if err != nil {
		return fmt.Errorf("configure ingest registry: %w", err)
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.Database.APIURL.Reveal())
	if err != nil {
		return errors.New("api: invalid database pool configuration")
	}
	poolConfig.MaxConns = 8
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("api: open database pool")
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		return errors.New("api: database readiness check failed")
	}
	if err = requireDatabaseRole(ctx, pool, "sentinelflow_api"); err != nil {
		return err
	}
	if err = configureExpectedSourceBindings(ctx, pool, cfg); err != nil {
		return err
	}

	store, err := repository.NewPostgreSQLBatchStore(pool)
	if err != nil {
		return fmt.Errorf("configure atomic batch store: %w", err)
	}
	ingest, err := api.NewIngestHandler(api.IngestConfig{Registry: registry, Store: store})
	if err != nil {
		return fmt.Errorf("configure ingest handler: %w", err)
	}
	bindingReconciler, err := authbinding.NewPostgreSQLReconciler(pool, authBindingBatchSize)
	if err != nil {
		return errors.New("api: configure auth binding reconciler")
	}

	managementAPI, err := configureManagementAPI(cfg, pool)
	if err != nil {
		return err
	}
	internal, management := newServers(cfg, ingest, managementAPI, pool)
	servers := []*http.Server{internal, management}
	listeners := make([]net.Listener, 0, len(servers))
	for _, server := range servers {
		listener, listenErr := net.Listen("tcp", server.Addr)
		if listenErr != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("api listener bind %s: %w", server.Addr, listenErr)
		}
		listeners = append(listeners, listener)
	}
	runtimeCtx, cancelRuntime := context.WithCancel(ctx)
	defer cancelRuntime()
	results := make(chan serverResult, len(servers))
	for index, server := range servers {
		name := "internal-ingest"
		if index == 1 {
			name = "management"
		}
		listener := listeners[index]
		go func(name string, server *http.Server, listener net.Listener) {
			logger.Info("api listener starting", "listener", name, "address", server.Addr)
			results <- serverResult{name: name, err: server.Serve(listener)}
		}(name, server, listener)
	}
	bindingResult := make(chan error, 1)
	go func() {
		bindingResult <- runAuthBinding(runtimeCtx, bindingReconciler, authBindingInterval)
	}()

	var serveErr error
	completed := 0
	bindingCompleted := false
	select {
	case <-ctx.Done():
		logger.Info("api shutdown requested")
	case result := <-results:
		completed++
		if result.err == nil {
			serveErr = fmt.Errorf("%s listener stopped unexpectedly", result.name)
		} else {
			serveErr = fmt.Errorf("%s listener stopped unexpectedly: %w", result.name, result.err)
		}
	case bindingErr := <-bindingResult:
		bindingCompleted = true
		if bindingErr == nil {
			serveErr = errors.New("api: auth binding reconciler stopped unexpectedly")
		} else {
			serveErr = bindingErr
		}
	}
	cancelRuntime()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil && serveErr == nil {
			serveErr = fmt.Errorf("api graceful shutdown: %w", err)
		}
	}
	for completed < len(servers) {
		select {
		case result := <-results:
			completed++
			if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) && serveErr == nil {
				serveErr = fmt.Errorf("%s listener shutdown: %w", result.name, result.err)
			}
		case <-shutdownCtx.Done():
			if serveErr == nil {
				serveErr = errors.New("api: listener shutdown timed out")
			}
			return serveErr
		}
	}
	if !bindingCompleted {
		select {
		case bindingErr := <-bindingResult:
			if bindingErr != nil && serveErr == nil {
				serveErr = bindingErr
			}
		case <-shutdownCtx.Done():
			if serveErr == nil {
				serveErr = errors.New("api: auth binding shutdown timed out")
			}
		}
	}
	return serveErr
}

type authBindingReconciler interface {
	Reconcile(context.Context) (authbinding.Result, error)
}

type databaseRoleReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type expectedSourceRegistrar interface {
	Register(context.Context, repository.ExpectedSourceBinding) (repository.RegisteredSourceBinding, error)
}

func configureExpectedSourceBindings(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) error {
	if ctx == nil || pool == nil {
		return errors.New("api: expected source registry unavailable")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return errors.New("api: begin expected source registration")
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	registry, err := repository.NewPostgreSQLSourceRegistry(tx)
	if err != nil {
		return errors.New("api: configure expected source registry")
	}
	if err = registerExpectedSourceBindings(ctx, registry, cfg); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("api: commit expected source registration")
	}
	return nil
}

func registerExpectedSourceBindings(ctx context.Context, registrar expectedSourceRegistrar, cfg config.Config) error {
	if ctx == nil || registrar == nil {
		return errors.New("api: expected source registry unavailable")
	}
	bindings := []repository.ExpectedSourceBinding{
		{
			BindingID:    cfg.Events.GatewaySourceBindingID,
			SenderID:     cfg.Events.GatewaySenderID,
			EndpointKind: repository.SourceEndpointGateway,
			ServiceLabel: cfg.Gateway.ServiceLabel,
			KeyID:        cfg.Events.GatewayHMACKeyID,
			ConfigDigest: "sha256:" + cfg.Events.GatewaySourceConfigHash,
		},
		{
			BindingID:    cfg.Events.AuthSourceBindingID,
			SenderID:     cfg.Events.AuthSenderID,
			EndpointKind: repository.SourceEndpointAuth,
			ServiceLabel: cfg.Events.AuthServiceLabel,
			KeyID:        cfg.Events.AuthHMACKeyID,
			ConfigDigest: "sha256:" + cfg.Events.AuthSourceConfigHash,
		},
	}
	for _, binding := range bindings {
		if _, err := registrar.Register(ctx, binding); err != nil {
			return fmt.Errorf("api: register expected %s source: %w", binding.EndpointKind, err)
		}
	}
	return nil
}

func requireDatabaseRole(ctx context.Context, reader databaseRoleReader, expected string) error {
	if ctx == nil || reader == nil || expected == "" {
		return errors.New("api: database role verification unavailable")
	}
	var current string
	if err := reader.QueryRow(ctx, "SELECT current_user::text").Scan(&current); err != nil {
		return errors.New("api: database role verification failed")
	}
	if current != expected {
		return errors.New("api: database connection has unexpected authority")
	}
	return nil
}

func runAuthBinding(ctx context.Context, reconciler authBindingReconciler, interval time.Duration) error {
	if ctx == nil || reconciler == nil || interval < time.Millisecond || interval > time.Minute {
		return errors.New("api: invalid auth binding runtime")
	}
	for {
		if _, err := reconciler.Reconcile(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("api: auth binding reconciliation failed")
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func decodeHMACKey(secret config.Secret) ([]byte, error) {
	encoded := secret.Reveal()
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(decoded) < 32 {
		return nil, errors.New("api: invalid event authentication key")
	}
	return decoded, nil
}

func newServers(
	cfg config.Config,
	ingest http.Handler,
	managementAPI http.Handler,
	pool interface{ Ping(context.Context) error },
) (*http.Server, *http.Server) {
	internalHandler := newInternalRouter(ingest, pool)
	managementHandler := newManagementRouter(managementAPI, pool)
	internalServer := newHTTPServer(cfg.Listeners.InternalAPIIngestAddr, internalHandler)
	managementServer := newHTTPServer(cfg.Listeners.APIManagementAddr, managementHandler)
	// Authenticated SSE has its own bounded per-write deadline and a short
	// maximum connection lifetime. A server-wide WriteTimeout would otherwise
	// terminate a healthy stream between heartbeats.
	managementServer.WriteTimeout = 0
	return internalServer, managementServer
}

func newInternalRouter(
	ingest http.Handler,
	pool interface{ Ping(context.Context) error },
) http.Handler {
	router := chi.NewRouter()
	router.NotFound(func(writer http.ResponseWriter, _ *http.Request) {
		writeNotFound(writer)
	})
	router.Handle(ingestion.GatewayEventsPath, ingest)
	router.Handle(ingestion.AuthEventsPath, ingest)
	registerHealthRoutes(router, pool)
	return controlPlaneRouter(router, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case ingestion.GatewayEventsPath, ingestion.AuthEventsPath:
			ingest.ServeHTTP(writer, request)
		case "/health/live", "/healthz":
			healthHandler(nil, false).ServeHTTP(writer, request)
		case "/health/ready", "/readyz":
			healthHandler(pool, true).ServeHTTP(writer, request)
		default:
			writeNotFound(writer)
		}
	}))
}

func newManagementRouter(
	managementAPI http.Handler,
	pool interface{ Ping(context.Context) error },
) http.Handler {
	router := chi.NewRouter()
	notFound := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeNotFound(writer)
	})
	router.NotFound(notFound)
	registerHealthRoutes(router, pool)

	// The management listener never exposes the internal ingest namespace.
	// Registering this boundary ahead of the catch-all also keeps listener
	// isolation explicit in the route tree rather than relying on a downstream
	// handler to reject an internal request.
	router.Handle("/internal", notFound)
	router.Handle("/internal/*", notFound)
	if managementAPI == nil {
		router.Handle("/*", notFound)
	} else {
		router.Handle("/*", managementAPI)
	}
	return controlPlaneRouter(router, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/health/live", "/healthz":
			healthHandler(nil, false).ServeHTTP(writer, request)
		case "/health/ready", "/readyz":
			healthHandler(pool, true).ServeHTTP(writer, request)
		default:
			if request.URL.Path == "/internal" || strings.HasPrefix(request.URL.Path, "/internal/") || managementAPI == nil {
				writeNotFound(writer)
				return
			}
			managementAPI.ServeHTTP(writer, request)
		}
	}))
}

// controlPlaneRouter rejects encoded path aliases before chi route lookup or
// any authentication/storage handler. Standard HTTP methods remain under chi's
// route tree. The compatibility handler is limited to extension methods that
// chi cannot look up, preserving the route-specific 404/405 and Allow behavior
// of the previous net/http composition without path cleaning or redirects.
func controlPlaneRouter(standard, extension http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request == nil || request.URL == nil || request.URL.RawPath != "" {
			writeNotFound(writer)
			return
		}
		if chiBuiltInMethod(request.Method) {
			standard.ServeHTTP(writer, request)
			return
		}
		extension.ServeHTTP(writer, request)
	})
}

func chiBuiltInMethod(method string) bool {
	switch method {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
		http.MethodOptions, http.MethodPatch, http.MethodPost, http.MethodPut,
		http.MethodTrace, "QUERY":
		return true
	default:
		return false
	}
}

func registerHealthRoutes(
	router chi.Router,
	pool interface{ Ping(context.Context) error },
) {
	live := healthHandler(nil, false)
	ready := healthHandler(pool, true)
	for _, path := range []string{"/health/live", "/healthz"} {
		router.Handle(path, live)
	}
	for _, path := range []string{"/health/ready", "/readyz"} {
		router.Handle(path, ready)
	}
}

func healthHandler(
	pool interface{ Ping(context.Context) error },
	checkReadiness bool,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writeMethodNotAllowed(writer)
			return
		}
		if checkReadiness {
			if pool == nil {
				writeHealth(writer, http.StatusServiceUnavailable)
				return
			}
			if err := pool.Ping(request.Context()); err != nil {
				writeHealth(writer, http.StatusServiceUnavailable)
				return
			}
		}
		writeHealth(writer, http.StatusNoContent)
	})
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
}

func writeHealth(writer http.ResponseWriter, status int) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
}

func writeMethodNotAllowed(writer http.ResponseWriter) {
	writer.Header().Set("Allow", "GET, HEAD")
	writeHealth(writer, http.StatusMethodNotAllowed)
}

func writeNotFound(writer http.ResponseWriter) {
	writeHealth(writer, http.StatusNotFound)
}
