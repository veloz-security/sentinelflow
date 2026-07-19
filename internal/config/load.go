package config

import (
	"encoding/base64"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var configuredNFTVersionPattern = regexp.MustCompile(`^nftables v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
var demoHistoryRunScopePattern = regexp.MustCompile(`^sentinelflow-demo-run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var demoHistoryImportIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func loadGateway(l *loader) GatewayConfig {
	return GatewayConfig{
		ServiceLabel:               l.eventLabel("SENTINELFLOW_SERVICE_LABEL", "demo-app"),
		ListenAddr:                 l.listenAddress("GATEWAY_LISTEN_ADDR", ":8080", false),
		MetricsListenAddr:          l.privateMetricsListenAddress("GATEWAY_METRICS_LISTEN_ADDR", "127.0.0.1:9090"),
		PublicHost:                 l.host("GATEWAY_PUBLIC_HOST", "localhost:8080"),
		UpstreamURL:                l.httpURL("GATEWAY_UPSTREAM_URL", "http://demo-app:8081", ""),
		UpstreamHost:               l.host("GATEWAY_UPSTREAM_HOST", "demo-app"),
		OriginCIDRs:                l.cidrs("GATEWAY_ORIGIN_CIDRS", "172.30.0.0/24", true, false),
		MaxHeaderBytes:             l.integer("GATEWAY_MAX_HEADER_BYTES", 32768, 1024, 1048576),
		MaxRequestTargetBytes:      l.integer("GATEWAY_MAX_REQUEST_TARGET_BYTES", 4096, 256, 4096),
		MaxClassificationPathBytes: l.integer("GATEWAY_MAX_CLASSIFICATION_PATH_BYTES", 2048, 128, 2048),
		MaxBodyBytes:               l.int64("GATEWAY_MAX_BODY_BYTES", 10485760, 1, 10485760),
		HeaderReadTimeout:          l.duration("GATEWAY_HEADER_READ_TIMEOUT", "5s", time.Millisecond, 5*time.Second),
		RequestTimeout:             l.duration("GATEWAY_REQUEST_TIMEOUT", "30s", time.Millisecond, 30*time.Second),
		UpstreamTimeout:            l.duration("GATEWAY_UPSTREAM_TIMEOUT", "30s", time.Millisecond, 30*time.Second),
		IdleTimeout:                l.duration("GATEWAY_IDLE_TIMEOUT", "60s", time.Second, 60*time.Second),
		EventQueueCapacity:         l.integer("GATEWAY_EVENT_QUEUE_CAPACITY", 10000, 1, 1000000),
		EventBatchSize:             l.integer("GATEWAY_EVENT_BATCH_SIZE", 100, 1, 100),
		EventMaxBatchBytes:         l.integer("GATEWAY_EVENT_MAX_BATCH_BYTES", 262144, 1024, 262144),
		EventFlushInterval:         l.duration("GATEWAY_EVENT_FLUSH_INTERVAL", "100ms", time.Millisecond, 5*time.Second),
		SenderCheckpointFile:       l.path("GATEWAY_SENDER_CHECKPOINT_FILE", "/var/lib/sentinelflow-gateway/sender-state.json", false),
		TLSCertFile:                l.path("GATEWAY_TLS_CERT_FILE", "", true),
		TLSKeyFile:                 l.path("GATEWAY_TLS_KEY_FILE", "", true),
		PathCatalogVersion:         l.text("PATH_CATALOG_VERSION", "path-catalog-v1"),
		AuthRoutePath:              l.text("AUTH_ROUTE_PATH", "/login"),
		AuthRouteLabel:             l.senderID("AUTH_ROUTE_LABEL", "login"),
	}
}

func loadListeners(l *loader) ListenerConfig {
	published := l.address("API_MANAGEMENT_PUBLISHED_HOST", "127.0.0.1")
	if published.IsValid() && !published.IsLoopback() {
		l.fail("API_MANAGEMENT_PUBLISHED_HOST", "must be an IPv4 loopback address")
	}
	return ListenerConfig{
		DemoOriginHTTPAddr:       l.listenAddress("DEMO_ORIGIN_HTTP_LISTEN_ADDR", "172.30.0.10:8081", true),
		InternalAPIIngestAddr:    l.listenAddress("INTERNAL_API_INGEST_LISTEN_ADDR", "172.31.0.10:8082", true),
		APIManagementAddr:        l.listenAddress("API_MANAGEMENT_LISTEN_ADDR", ":8083", false),
		APIManagementPublishHost: published,
	}
}

func loadEvents(l *loader) EventConfig {
	return EventConfig{
		GatewayIngestURL:        l.httpURL("INTERNAL_GATEWAY_INGEST_URL", "http://api:8082/internal/v1/gateway-events", "/internal/v1/gateway-events"),
		AuthIngestURL:           l.httpURL("INTERNAL_AUTH_INGEST_URL", "http://api:8082/internal/v1/auth-events", "/internal/v1/auth-events"),
		GatewaySenderID:         l.senderID("GATEWAY_EVENT_SENDER_ID", "gateway-01"),
		GatewayHMACKeyID:        l.optionalSafeID("GATEWAY_EVENT_HMAC_KEY_ID"),
		GatewayHMACKey:          l.base64Secret("GATEWAY_EVENT_HMAC_KEY"),
		GatewaySourceBindingID:  l.optionalUUID("GATEWAY_EXPECTED_SOURCE_BINDING_ID"),
		GatewaySourceConfigHash: l.optionalDigest("GATEWAY_SOURCE_CONFIG_SHA256"),
		AuthSenderID:            l.senderID("AUTH_EVENT_SENDER_ID", "demo-app"),
		AuthServiceLabel:        l.enum("AUTH_EVENT_SERVICE_LABEL", "demo-app", "demo-app"),
		AuthHMACKeyID:           l.optionalSafeID("AUTH_EVENT_HMAC_KEY_ID"),
		AuthHMACKey:             l.base64Secret("AUTH_EVENT_HMAC_KEY"),
		AuthSourceBindingID:     l.optionalUUID("AUTH_EXPECTED_SOURCE_BINDING_ID"),
		AuthSourceConfigHash:    l.optionalDigest("AUTH_SOURCE_CONFIG_SHA256"),
		AuthAccountHashKey:      l.base64Secret("AUTH_ACCOUNT_HASH_KEY"),
		AuthCheckpointFile:      l.path("AUTH_EVENT_SENDER_CHECKPOINT_FILE", "/var/lib/sentinelflow-auth-adapter/sender-state.json", false),
		AuthBindingTimeout:      l.duration("AUTH_EVENT_BINDING_TIMEOUT", "5m", time.Second, 5*time.Minute),
		MaxFutureSkew:           l.duration("EVENT_MAX_FUTURE_SKEW", "60s", time.Second, 60*time.Second),
		MaxPastSkew:             l.duration("EVENT_MAX_PAST_SKEW", "5m", time.Second, 5*time.Minute),
	}
}

func loadDatabase(l *loader) DatabaseConfig {
	return DatabaseConfig{
		MigrationURL:  l.databaseURL("DATABASE_MIGRATION_URL"),
		APIURL:        l.databaseURL("DATABASE_API_URL"),
		WorkerURL:     l.databaseURL("DATABASE_WORKER_URL"),
		ReadURL:       l.databaseURL("DATABASE_READ_URL"),
		DispatcherURL: l.databaseURL("DATABASE_DISPATCHER_URL"),
	}
}

func loadOpenAI(l *loader) OpenAIConfig {
	return OpenAIConfig{
		APIKey:                   l.opaqueSecret("OPENAI_API_KEY"),
		Model:                    l.enum("OPENAI_MODEL", "gpt-5.6-sol", "gpt-5.6-sol"),
		ReasoningEffort:          l.enum("OPENAI_REASONING_EFFORT", "medium", "medium"),
		Store:                    l.boolean("OPENAI_STORE", false),
		InputSchemaFile:          l.path("OPENAI_INPUT_SCHEMA_FILE", "contracts/ai/sentinelflow_analysis_input_v1.schema.json", false),
		SystemPromptFile:         l.path("OPENAI_SYSTEM_PROMPT_FILE", "contracts/ai/sentinelflow_system_prompt_v1.txt", false),
		OutputSchemaFile:         l.path("OPENAI_OUTPUT_SCHEMA_FILE", "contracts/ai/sentinelflow_analysis_v1.schema.json", false),
		MaxEvidenceRefs:          l.integer("OPENAI_MAX_EVIDENCE_REFS", 50, 1, 50),
		MaxInputBytes:            l.integer("OPENAI_MAX_INPUT_BYTES", 12288, 1024, 12288),
		MaxOutputTokens:          l.integer("OPENAI_MAX_OUTPUT_TOKENS", 2048, 1, 2048),
		Timeout:                  l.duration("OPENAI_TIMEOUT", "30s", time.Second, 30*time.Second),
		MaxTransientRetries:      l.integer("OPENAI_MAX_TRANSIENT_RETRIES", 1, 0, 1),
		MaxConcurrency:           l.integer("OPENAI_MAX_CONCURRENCY", 2, 1, 2),
		DailyBudgetUSD:           l.decimal("OPENAI_DAILY_BUDGET_USD", 10, 0.01, 1000000, false),
		RateCardVersion:          l.optionalText("OPENAI_RATE_CARD_VERSION"),
		InputUSDPerMillion:       l.decimal("OPENAI_INPUT_USD_PER_1M_TOKENS", 0, 0.000001, 1000000, true),
		CachedInputUSDPerMillion: l.decimal("OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS", 0, 0.000001, 1000000, true),
		OutputUSDPerMillion:      l.decimal("OPENAI_OUTPUT_USD_PER_1M_TOKENS", 0, 0.000001, 1000000, true),
		BudgetTimezone:           l.enum("OPENAI_BUDGET_TIMEZONE", "UTC", "UTC"),
	}
}

func loadAdmin(l *loader) AdminConfig {
	hash := l.opaqueSecret("ADMIN_PASSWORD_ARGON2ID_HASH")
	if hash.IsSet() && !validateArgon2idPHC(hash.Reveal()) {
		l.fail("ADMIN_PASSWORD_ARGON2ID_HASH", "must be a canonical Argon2id v=19 PHC string within the supported resource bounds")
	}
	origins := l.origins("ADMIN_ALLOWED_ORIGINS", "http://localhost:4173,http://localhost:5173")
	if !validAdminOrigins(origins) {
		l.fail("ADMIN_ALLOWED_ORIGINS", "must contain 1 to 32 unique canonical HTTPS origins or explicit localhost HTTP origins")
	}
	transport := AdminCookieTransport(l.enum(
		"ADMIN_COOKIE_TRANSPORT",
		string(AdminCookieTransportLocalTest),
		string(AdminCookieTransportTLS),
		string(AdminCookieTransportLocalTest),
	))
	defaultCookieName := "sentinelflow_admin"
	if transport == AdminCookieTransportTLS {
		defaultCookieName = "__Host-sentinelflow"
	}
	cookieName := l.text("ADMIN_SESSION_COOKIE_NAME", defaultCookieName)
	if !validCookieName(cookieName) {
		l.fail("ADMIN_SESSION_COOKIE_NAME", "must be a valid HTTP cookie name")
	}
	return AdminConfig{
		Username:                l.text("ADMIN_USERNAME", "admin"),
		PasswordArgon2idHash:    hash,
		SessionHMACKey:          l.base64Secret("SESSION_HMAC_KEY"),
		AllowedOrigins:          origins,
		SessionCookieName:       cookieName,
		CookieTransport:         transport,
		SessionTTL:              l.duration("SESSION_TTL", "8h", time.Minute, 8*time.Hour),
		SessionIdleTimeout:      l.duration("SESSION_IDLE_TIMEOUT", "30m", time.Minute, 30*time.Minute),
		HILReauthAfter:          l.duration("HIL_REAUTH_AFTER", "15m", time.Minute, 15*time.Minute),
		HILChallengeTTL:         l.duration("HIL_CHALLENGE_TTL", "5m", time.Second, 5*time.Minute),
		HILDecisionsPerMinute:   l.integer("HIL_DECISION_RATE_LIMIT_PER_MINUTE", 5, 1, 5),
		LoginPerSourcePerMinute: l.integer("ADMIN_LOGIN_RATE_LIMIT_PER_SOURCE_PER_MINUTE", 5, 1, 5),
		LoginGlobalPerMinute:    l.integer("ADMIN_LOGIN_RATE_LIMIT_GLOBAL_PER_MINUTE", 20, 1, 20),
	}
}

func loadDetection(l *loader) DetectionConfig {
	return DetectionConfig{
		PathScanUniquePaths:              l.integer("DETECT_PATH_SCAN_UNIQUE_PATHS", 8, 1, 10000),
		PathScanWindow:                   l.duration("DETECT_PATH_SCAN_WINDOW", "60s", time.Second, 24*time.Hour),
		SuspiciousPathIDs:                l.csv("DETECT_SUSPICIOUS_PATH_IDS", "admin_console,env_file,git_config,wp_admin,phpmyadmin,server_status,actuator_env,backup_archive"),
		RequestBurstCount:                l.integer("DETECT_REQUEST_BURST_COUNT", 120, 1, 1000000),
		RequestBurstWindow:               l.duration("DETECT_REQUEST_BURST_WINDOW", "10s", time.Second, 24*time.Hour),
		BruteForceFailures:               l.integer("DETECT_BRUTE_FORCE_FAILURES", 10, 1, 1000000),
		BruteForceWindow:                 l.duration("DETECT_BRUTE_FORCE_WINDOW", "60s", time.Second, 24*time.Hour),
		CredentialStuffingFailures:       l.integer("DETECT_CREDENTIAL_STUFFING_FAILURES", 20, 1, 1000000),
		CredentialStuffingUniqueAccounts: l.integer("DETECT_CREDENTIAL_STUFFING_UNIQUE_ACCOUNTS", 8, 1, 1000000),
		CredentialStuffingWindow:         l.duration("DETECT_CREDENTIAL_STUFFING_WINDOW", "5m", time.Second, 24*time.Hour),
	}
}

func loadIncidents(l *loader) IncidentConfig {
	return IncidentConfig{
		CorrelationWindow: l.duration("INCIDENT_CORRELATION_WINDOW", "5m", time.Second, 24*time.Hour),
		CloseAfter:        l.duration("INCIDENT_CLOSE_AFTER", "15m", time.Second, 24*time.Hour),
		ReopenWithin:      l.duration("INCIDENT_REOPEN_WITHIN", "30m", time.Second, 24*time.Hour),
	}
}

func loadEnforcement(l *loader) EnforcementConfig {
	hostEnabled := l.boolean("HOST_ENFORCEMENT_ENABLED", false)
	if hostEnabled {
		l.fail("HOST_ENFORCEMENT_ENABLED", "host enforcement is unsupported in v0.1")
		hostEnabled = false
	}
	return EnforcementConfig{
		NFTBinary:                     l.text("NFT_BINARY", "/usr/sbin/nft"),
		NFTBinaryExpectedSHA256:       l.optionalDigest("NFT_BINARY_EXPECTED_SHA256"),
		NFTExpectedVersion:            l.optionalText("NFT_EXPECTED_VERSION"),
		NFTFamily:                     l.enum("NFT_FAMILY", "inet", "inet"),
		NFTTable:                      l.enum("NFT_TABLE", "sentinelflow", "sentinelflow"),
		NFTBlacklistSet:               l.enum("NFT_BLACKLIST_SET", "blacklist_ipv4", "blacklist_ipv4"),
		NFTInputChain:                 l.enum("NFT_INPUT_CHAIN", "gateway_input", "gateway_input"),
		NFTProtectedTCPPort:           l.integer("NFT_PROTECTED_TCP_PORT", 8080, 1, 65535),
		NFTInputPriority:              l.integer("NFT_INPUT_PRIORITY", 0, -1000, 1000),
		BaseChainSchemaVersion:        l.enum("NFT_BASE_CHAIN_SCHEMA_VERSION", "nft-base-chain-v1", "nft-base-chain-v1"),
		BaseChainContract:             l.path("NFT_BASE_CHAIN_CONTRACT", "contracts/enforcement/nft_base_chain_v1.nft", false),
		BaseChainExpectedSHA256:       l.digest("NFT_BASE_CHAIN_EXPECTED_SHA256", "2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488"),
		BaseChainLiveContract:         l.path("NFT_BASE_CHAIN_LIVE_CONTRACT", "contracts/enforcement/nft_base_chain_v1.live.json", false),
		BaseChainLiveExpectedSHA256:   l.digest("NFT_BASE_CHAIN_LIVE_EXPECTED_SHA256", "d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997"),
		ValidatorSocket:               l.path("NFT_VALIDATOR_SOCKET", "/run/sentinelflow-validator/validator.sock", false),
		ExecutorSocket:                l.path("EXECUTOR_SOCKET", "/run/sentinelflow-executor/executor.sock", false),
		ExecutorReplayJournal:         l.path("EXECUTOR_REPLAY_JOURNAL", "/var/lib/sentinelflow-executor/replay.json", false),
		ExecutorStartupMode:           ExecutorStartupMode(l.enum("EXECUTOR_STARTUP_MODE", "verify", "verify", "bootstrap")),
		ExecutorMaxFrameBytes:         l.integer("EXECUTOR_MAX_FRAME_BYTES", 16384, 1, 16384),
		ExecutorIOTimeout:             l.duration("EXECUTOR_IO_TIMEOUT", "2s", time.Millisecond, 2*time.Second),
		DispatchCapabilityTTL:         l.duration("DISPATCH_CAPABILITY_TTL", "60s", time.Second, 60*time.Second),
		DispatcherSigningKeyFile:      l.secretFile("DISPATCHER_SIGNING_PRIVATE_KEY_FILE"),
		ExecutorDispatchPublicKeyFile: l.secretFile("EXECUTOR_DISPATCH_PUBLIC_KEY_FILE"),
		ExecutorResultPrivateKeyFile:  l.secretFile("EXECUTOR_RESULT_PRIVATE_KEY_FILE"),
		DispatcherResultPublicKeyFile: l.secretFile("DISPATCHER_RESULT_PUBLIC_KEY_FILE"),
		BlockTTLMin:                   l.duration("BLOCK_TTL_MIN", "1m", time.Minute, 24*time.Hour),
		BlockTTLDefault:               l.duration("BLOCK_TTL_DEFAULT", "30m", time.Minute, 24*time.Hour),
		BlockTTLMax:                   l.duration("BLOCK_TTL_MAX", "24h", time.Minute, 24*time.Hour),
		ValidationTTL:                 l.duration("VALIDATION_TTL", "5m", time.Second, 5*time.Minute),
		ApprovalTTL:                   l.duration("APPROVAL_TTL", "5m", time.Second, 5*time.Minute),
		HistoricalImpactLookback:      l.duration("HISTORICAL_IMPACT_LOOKBACK", "24h", time.Minute, 30*24*time.Hour),
		ProtectedIPv4Contract:         l.path("PROTECTED_IPV4_CONTRACT", "contracts/enforcement/protected_ipv4_v1.json", false),
		ProtectedIPv4ExpectedSHA256:   l.digest("PROTECTED_IPV4_EXPECTED_SHA256", "d3dfb63a573925e19f29e8595fd5574bc441a9c468d2f9ef6d2f004abb101104"),
		ProtectedCIDRs:                l.cidrs("PROTECTED_CIDRS", "", false, true),
		ProtectedOriginIPv4:           l.addresses("PROTECTED_ORIGIN_IPV4", ""),
		ProtectedGatewayIPv4:          l.addresses("PROTECTED_GATEWAY_IPV4", ""),
		ProtectedExecutorIPv4:         l.addresses("PROTECTED_EXECUTOR_IPV4", ""),
		ProtectedManagementIPv4:       l.addresses("PROTECTED_MANAGEMENT_IPV4", ""),
		ProtectedCurrentAdminIPv4:     l.addresses("PROTECTED_CURRENT_ADMIN_IPV4", ""),
		HostEnforcementEnabled:        hostEnabled,
	}
}

func loadDemo(l *loader) DemoConfig {
	return DemoConfig{
		GatewayPeerCIDRs:                      l.cidrs("DEMO_GATEWAY_PEER_CIDRS", "172.30.0.2/32", true, true),
		AllowRFC5737:                          l.boolean("DEMO_ALLOW_RFC5737", false),
		EnforcementIsolationVerified:          l.boolean("DEMO_ENFORCEMENT_ISOLATION_VERIFIED", false),
		HostRulesetUnchanged:                  l.boolean("DEMO_HOST_RULESET_UNCHANGED", false),
		ClientCIDR:                            l.prefix("DEMO_CLIENT_CIDR", "203.0.113.0/24"),
		AttackSourceIP:                        l.address("DEMO_ATTACK_SOURCE_IP", "203.0.113.20"),
		TestClock:                             l.rfc3339("DEMO_TEST_CLOCK", "2026-07-18T02:00:00Z"),
		HistoryFixtureDataset:                 l.path("DEMO_HISTORY_FIXTURE_DATASET", "contracts/fixtures/demo_history_dataset_v1.json", false),
		HistoryDatasetExpectedSHA256:          l.digest("DEMO_HISTORY_DATASET_EXPECTED_SHA256", "0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00"),
		HistoryFixtureManifest:                l.path("DEMO_HISTORY_FIXTURE_MANIFEST", "contracts/fixtures/demo_history_manifest_v1.json", false),
		HistoryImportID:                       l.text("DEMO_HISTORY_IMPORT_ID", "019b0000-0000-7000-8000-000000000501"),
		ContractVectorBundle:                  l.path("CONTRACT_VECTOR_BUNDLE", "contracts/vectors/contract_vectors_v1.json", false),
		HistoryPublicKeyFile:                  l.secretFile("DEMO_HISTORY_PUBLIC_KEY_FILE"),
		HistorySimulatorPrivateKeyFile:        l.secretFile("DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE"),
		HistorySignedEnvelopeFile:             l.path("DEMO_HISTORY_SIGNED_ENVELOPE_FILE", "", true),
		HistoryAnalysisActivationSecretFile:   l.secretFile("DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE"),
		HistoryValidationActivationSecretFile: l.secretFile("DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE"),
		HistoryPublicKeyB64URL:                l.optionalText("DEMO_HISTORY_PUBLIC_KEY_B64URL"),
		HistoryRunScope:                       l.optionalText("DEMO_HISTORY_RUN_SCOPE"),
		HistoryClockAt:                        l.optionalMillisecondUTC("DEMO_HISTORY_CLOCK_AT"),
		HistoryImpactSourceHealthDigest:       l.optionalSHA256Digest("DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"),
	}
}

func loadRetention(l *loader) RetentionConfig {
	return RetentionConfig{
		EventEvidence:    l.duration("EVENT_EVIDENCE_RETENTION", "168h", time.Hour, 168*time.Hour),
		IncidentAIPolicy: l.duration("INCIDENT_AI_POLICY_RETENTION", "720h", time.Hour, 720*time.Hour),
		Audit:            l.duration("AUDIT_RETENTION", "2160h", time.Hour, 2160*time.Hour),
	}
}

func validateCrossFields(l *loader, c *Config) {
	for _, database := range []struct {
		name  string
		value Secret
	}{
		{"DATABASE_MIGRATION_URL", c.Database.MigrationURL},
		{"DATABASE_API_URL", c.Database.APIURL},
		{"DATABASE_WORKER_URL", c.Database.WorkerURL},
		{"DATABASE_READ_URL", c.Database.ReadURL},
		{"DATABASE_DISPATCHER_URL", c.Database.DispatcherURL},
	} {
		if !database.value.IsSet() {
			continue
		}
		parsed, err := url.Parse(database.value.Reveal())
		if err != nil {
			continue
		}
		if c.Environment == EnvironmentProduction && parsed.Query().Get("sslmode") != "verify-full" {
			l.fail(database.name, "must use sslmode=verify-full in production")
		}
	}
	if c.Role == RoleValidationWorker && c.Database.WorkerURL.IsSet() {
		parsed, err := url.Parse(c.Database.WorkerURL.Reveal())
		if err != nil || parsed.User == nil || parsed.User.Username() != "sentinelflow_worker" ||
			parsed.Path != "/sentinelflow" {
			l.fail("DATABASE_WORKER_URL", "must use the canonical sentinelflow_worker role and database")
		}
	}
	if c.Enforcement.NFTBinary != "/usr/sbin/nft" {
		l.fail("NFT_BINARY", "must remain the fixed absolute nftables binary path")
	}
	if c.Enforcement.NFTExpectedVersion != "" && !configuredNFTVersionPattern.MatchString(c.Enforcement.NFTExpectedVersion) {
		l.fail("NFT_EXPECTED_VERSION", "must be a normalized nftables version")
	}
	if c.Enforcement.ValidatorSocket == "" || !filepath.IsAbs(c.Enforcement.ValidatorSocket) ||
		filepath.Clean(c.Enforcement.ValidatorSocket) != c.Enforcement.ValidatorSocket ||
		len(c.Enforcement.ValidatorSocket) > 100 {
		l.fail("NFT_VALIDATOR_SOCKET", "must be a clean absolute Unix socket path")
	}
	if c.Enforcement.BaseChainExpectedSHA256 != "2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488" {
		l.fail("NFT_BASE_CHAIN_EXPECTED_SHA256", "must match the frozen v0.1 raw base-chain contract")
	}
	if c.Enforcement.BaseChainLiveExpectedSHA256 != "d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997" {
		l.fail("NFT_BASE_CHAIN_LIVE_EXPECTED_SHA256", "must match the frozen v0.1 live-schema contract")
	}
	if c.Enforcement.ProtectedIPv4ExpectedSHA256 != "d3dfb63a573925e19f29e8595fd5574bc441a9c468d2f9ef6d2f004abb101104" {
		l.fail("PROTECTED_IPV4_EXPECTED_SHA256", "must match the frozen v0.1 protected-IPv4 contract")
	}
	if (c.Gateway.TLSCertFile == "") != (c.Gateway.TLSKeyFile == "") {
		l.fail("GATEWAY_TLS_CERT_FILE", "certificate and key files must be configured together")
	}
	if len(c.Gateway.OriginCIDRs) == 0 {
		l.fail("GATEWAY_ORIGIN_CIDRS", "must contain at least one private origin CIDR")
	}
	if c.Gateway.MaxClassificationPathBytes > c.Gateway.MaxRequestTargetBytes {
		l.fail("GATEWAY_MAX_CLASSIFICATION_PATH_BYTES", "must not exceed the request-target limit")
	}
	if c.Gateway.EventBatchSize > c.Gateway.EventQueueCapacity {
		l.fail("GATEWAY_EVENT_BATCH_SIZE", "must not exceed the queue capacity")
	}
	if c.OpenAI.Store {
		l.fail("OPENAI_STORE", "must remain false")
	}
	if c.OpenAI.MaxEvidenceRefs != 50 {
		l.fail("OPENAI_MAX_EVIDENCE_REFS", "must remain 50 for the frozen analysis contract")
	}
	if c.OpenAI.MaxInputBytes != 12288 {
		l.fail("OPENAI_MAX_INPUT_BYTES", "must remain 12288 for the frozen analysis contract")
	}
	if c.OpenAI.MaxOutputTokens != 2048 {
		l.fail("OPENAI_MAX_OUTPUT_TOKENS", "must remain 2048 for the frozen analysis contract")
	}
	if c.Admin.SessionIdleTimeout > c.Admin.SessionTTL {
		l.fail("SESSION_IDLE_TIMEOUT", "must not exceed the session TTL")
	}
	// The v0.1 administrator boundary deliberately freezes these values. The
	// adminauth package enforces the same constants internally; accepting a
	// different environment value here would create a dangerous configuration
	// that appears active but is silently ignored at runtime.
	if c.Admin.SessionTTL != 8*time.Hour {
		l.fail("SESSION_TTL", "must remain 8h for the frozen v0.1 administrator contract")
	}
	if c.Admin.SessionIdleTimeout != 30*time.Minute {
		l.fail("SESSION_IDLE_TIMEOUT", "must remain 30m for the frozen v0.1 administrator contract")
	}
	if c.Admin.HILReauthAfter != 15*time.Minute {
		l.fail("HIL_REAUTH_AFTER", "must remain 15m for the frozen v0.1 administrator contract")
	}
	if c.Admin.HILDecisionsPerMinute != 5 {
		l.fail("HIL_DECISION_RATE_LIMIT_PER_MINUTE", "must remain 5 for the frozen v0.1 administrator contract")
	}
	if c.Admin.LoginPerSourcePerMinute != 5 {
		l.fail("ADMIN_LOGIN_RATE_LIMIT_PER_SOURCE_PER_MINUTE", "must remain 5 for the frozen v0.1 administrator contract")
	}
	if c.Admin.LoginGlobalPerMinute != 20 {
		l.fail("ADMIN_LOGIN_RATE_LIMIT_GLOBAL_PER_MINUTE", "must remain 20 for the frozen v0.1 administrator contract")
	}
	if c.Enforcement.BlockTTLMin > c.Enforcement.BlockTTLDefault || c.Enforcement.BlockTTLDefault > c.Enforcement.BlockTTLMax {
		l.fail("BLOCK_TTL_DEFAULT", "must be between the minimum and maximum TTL")
	}
	if c.Enforcement.ValidationTTL > 5*time.Minute || c.Enforcement.ApprovalTTL > 5*time.Minute {
		l.fail("VALIDATION_TTL", "validation and approval validity must not exceed five minutes")
	}
	if c.Demo.AttackSourceIP.IsValid() && c.Demo.ClientCIDR.IsValid() && !c.Demo.ClientCIDR.Contains(c.Demo.AttackSourceIP) {
		l.fail("DEMO_ATTACK_SOURCE_IP", "must be inside DEMO_CLIENT_CIDR")
	}
	if c.Demo.HistoryPublicKeyB64URL != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(c.Demo.HistoryPublicKeyB64URL)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != c.Demo.HistoryPublicKeyB64URL {
			l.fail("DEMO_HISTORY_PUBLIC_KEY_B64URL", "must be canonical unpadded base64url for 32 bytes")
		}
	}
	if c.Demo.HistoryRunScope != "" && !demoHistoryRunScopePattern.MatchString(c.Demo.HistoryRunScope) {
		l.fail("DEMO_HISTORY_RUN_SCOPE", "must be a run-scoped demo identifier")
	}
	if c.Demo.HistoryImpactSourceHealthDigest != "" &&
		c.Demo.HistoryImpactSourceHealthDigest != "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3" {
		l.fail("DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST", "must match the exact v0.1 query projection")
	}
	if c.Demo.HistoryImportID != "" && !demoHistoryImportIDPattern.MatchString(c.Demo.HistoryImportID) {
		l.fail("DEMO_HISTORY_IMPORT_ID", "must be a canonical UUID")
	}
	for index, prefix := range c.Demo.GatewayPeerCIDRs {
		if prefix.Bits() < 24 {
			l.fail("DEMO_GATEWAY_PEER_CIDRS", "must contain only /24 or narrower private Gateway peer CIDRs")
			break
		}
		for _, previous := range c.Demo.GatewayPeerCIDRs[:index] {
			if previous.Overlaps(prefix) {
				l.fail("DEMO_GATEWAY_PEER_CIDRS", "must not contain overlapping Gateway peer CIDRs")
				break
			}
		}
	}
	if c.Demo.AllowRFC5737 && c.Environment != EnvironmentDemo && c.Environment != EnvironmentTest {
		l.fail("DEMO_ALLOW_RFC5737", "may be true only in demo or test environments")
	}
	if c.Environment == EnvironmentProduction && c.Demo.AllowRFC5737 {
		l.fail("DEMO_ALLOW_RFC5737", "must be false in production")
	}
	if c.Demo.AllowRFC5737 && !c.Demo.EnforcementIsolationVerified {
		l.fail("DEMO_ENFORCEMENT_ISOLATION_VERIFIED", "must be true for the isolated RFC 5737 demo exception")
	}
	if c.Demo.AllowRFC5737 && !c.Demo.HostRulesetUnchanged {
		l.fail("DEMO_HOST_RULESET_UNCHANGED", "must be true for the isolated RFC 5737 demo exception")
	}
	if !c.Demo.AllowRFC5737 && c.Demo.EnforcementIsolationVerified {
		l.fail("DEMO_ENFORCEMENT_ISOLATION_VERIFIED", "must be false when the RFC 5737 demo exception is disabled")
	}
	if !c.Demo.AllowRFC5737 && c.Demo.HostRulesetUnchanged {
		l.fail("DEMO_HOST_RULESET_UNCHANGED", "must be false when the RFC 5737 demo exception is disabled")
	}
	if c.Enforcement.ExecutorStartupMode == ExecutorStartupBootstrap {
		if c.Role != RoleExecutor {
			l.fail("EXECUTOR_STARTUP_MODE", "bootstrap is valid only for the executor role")
		}
		if c.Environment != EnvironmentDemo && c.Environment != EnvironmentTest {
			l.fail("EXECUTOR_STARTUP_MODE", "bootstrap is restricted to isolated demo or test environments")
		}
		if !c.Demo.AllowRFC5737 || !c.Demo.EnforcementIsolationVerified || !c.Demo.HostRulesetUnchanged {
			l.fail("EXECUTOR_STARTUP_MODE", "bootstrap requires all isolated demo enforcement proofs")
		}
	}
	if c.Gateway.UpstreamURL.Hostname() != "" {
		allowed := false
		for _, prefix := range c.Gateway.OriginCIDRs {
			if addr, err := netip.ParseAddr(c.Gateway.UpstreamURL.Hostname()); err == nil && prefix.Contains(addr) {
				allowed = true
			}
		}
		// DNS names are revalidated by the Gateway resolver/dialer. A literal IP
		// must already be inside an allowed origin prefix.
		if _, err := netip.ParseAddr(c.Gateway.UpstreamURL.Hostname()); err == nil && !allowed {
			l.fail("GATEWAY_UPSTREAM_URL", "literal origin address is outside GATEWAY_ORIGIN_CIDRS")
		}
	}
	if strings.TrimSpace(c.Admin.Username) == "" {
		l.fail("ADMIN_USERNAME", "must not be empty")
	}
	if c.Role == RoleAPI && c.Environment == EnvironmentProduction {
		if c.Admin.CookieTransport != AdminCookieTransportTLS {
			l.fail("ADMIN_COOKIE_TRANSPORT", "must be tls for the production API")
		}
		if !strings.HasPrefix(c.Admin.SessionCookieName, "__Host-") {
			l.fail("ADMIN_SESSION_COOKIE_NAME", "must use the __Host- prefix for the production API")
		}
		for _, origin := range c.Admin.AllowedOrigins {
			if !strings.HasPrefix(origin, "https://") {
				l.fail("ADMIN_ALLOWED_ORIGINS", "must contain only HTTPS origins for the production API")
				break
			}
		}
	}
}

func validateRequiredSecrets(l *loader, c *Config) {
	requireSecret := func(name string, secret Secret) {
		if !secret.IsSet() {
			l.fail(name, "is required for service role "+string(c.Role))
		}
	}
	requireFile := func(name, value string) {
		if value == "" {
			l.fail(name, "is required for service role "+string(c.Role))
		}
	}
	requireText := requireFile
	requireExplicitText := func(name string) {
		value, ok := l.lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			l.fail(name, "is required for service role "+string(c.Role))
		}
	}

	switch c.Role {
	case RoleGateway:
		requireSecret("GATEWAY_EVENT_HMAC_KEY", c.Events.GatewayHMACKey)
	case RoleAPI:
		requireSecret("DATABASE_API_URL", c.Database.APIURL)
		requireSecret("GATEWAY_EVENT_HMAC_KEY", c.Events.GatewayHMACKey)
		requireSecret("AUTH_EVENT_HMAC_KEY", c.Events.AuthHMACKey)
		requireSecret("ADMIN_PASSWORD_ARGON2ID_HASH", c.Admin.PasswordArgon2idHash)
		requireSecret("SESSION_HMAC_KEY", c.Admin.SessionHMACKey)
		requireText("GATEWAY_EVENT_HMAC_KEY_ID", c.Events.GatewayHMACKeyID)
		requireText("AUTH_EVENT_HMAC_KEY_ID", c.Events.AuthHMACKeyID)
		requireText("GATEWAY_EXPECTED_SOURCE_BINDING_ID", c.Events.GatewaySourceBindingID)
		requireText("AUTH_EXPECTED_SOURCE_BINDING_ID", c.Events.AuthSourceBindingID)
		requireText("GATEWAY_SOURCE_CONFIG_SHA256", c.Events.GatewaySourceConfigHash)
		requireText("AUTH_SOURCE_CONFIG_SHA256", c.Events.AuthSourceConfigHash)
	case RoleDetector:
		requireSecret("DATABASE_WORKER_URL", c.Database.WorkerURL)
	case RoleWorker:
		requireSecret("DATABASE_WORKER_URL", c.Database.WorkerURL)
		requireSecret("OPENAI_API_KEY", c.OpenAI.APIKey)
		if c.OpenAI.RateCardVersion == "" {
			l.fail("OPENAI_RATE_CARD_VERSION", "is required for service role worker")
		}
		if c.OpenAI.InputUSDPerMillion <= 0 || c.OpenAI.CachedInputUSDPerMillion <= 0 || c.OpenAI.OutputUSDPerMillion <= 0 {
			l.fail("OPENAI_INPUT_USD_PER_1M_TOKENS", "all operator rate-card values are required for service role worker")
		}
		if c.Environment == EnvironmentDemo {
			for _, name := range []string{
				"DEMO_HISTORY_SIGNED_ENVELOPE_FILE", "DEMO_HISTORY_PUBLIC_KEY_B64URL",
				"DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID", "DEMO_HISTORY_CLOCK_AT",
				"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST", "DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
			} {
				requireExplicitText(name)
			}
			if c.Demo.HistoryClockAt.IsZero() {
				l.fail("DEMO_HISTORY_CLOCK_AT", "is required for demo analysis history")
			}
			if c.Demo.HistoryAnalysisActivationSecretFile != DemoHistoryAnalysisActivationPath {
				l.fail("DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE", "must use the fixed analysis capability path")
			}
		}
	case RoleValidationWorker:
		requireSecret("DATABASE_WORKER_URL", c.Database.WorkerURL)
		if c.Enforcement.NFTBinaryExpectedSHA256 == "" {
			l.fail("NFT_BINARY_EXPECTED_SHA256", "is required for service role validation-worker")
		}
		if c.Enforcement.NFTExpectedVersion == "" {
			l.fail("NFT_EXPECTED_VERSION", "is required for service role validation-worker")
		}
		if len(c.Enforcement.ProtectedCurrentAdminIPv4) == 0 {
			l.fail("PROTECTED_CURRENT_ADMIN_IPV4", "is required for service role validation-worker")
		}
		if c.Environment == EnvironmentDemo {
			for _, name := range []string{
				"DEMO_HISTORY_SIGNED_ENVELOPE_FILE", "DEMO_HISTORY_PUBLIC_KEY_B64URL",
				"DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID", "DEMO_HISTORY_CLOCK_AT",
				"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST", "DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
			} {
				requireExplicitText(name)
			}
			if c.Demo.HistoryClockAt.IsZero() {
				l.fail("DEMO_HISTORY_CLOCK_AT", "is required for demo validation history")
			}
			if c.Demo.HistoryValidationActivationSecretFile != DemoHistoryValidationActivationPath {
				l.fail("DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE", "must use the fixed validation capability path")
			}
		}
	case RoleValidator:
		if c.Enforcement.NFTBinaryExpectedSHA256 == "" {
			l.fail("NFT_BINARY_EXPECTED_SHA256", "is required for service role validator")
		}
		if c.Enforcement.NFTExpectedVersion == "" {
			l.fail("NFT_EXPECTED_VERSION", "is required for service role validator")
		}
	case RoleDispatcher:
		requireSecret("DATABASE_DISPATCHER_URL", c.Database.DispatcherURL)
		requireFile("DISPATCHER_SIGNING_PRIVATE_KEY_FILE", c.Enforcement.DispatcherSigningKeyFile)
		requireFile("DISPATCHER_RESULT_PUBLIC_KEY_FILE", c.Enforcement.DispatcherResultPublicKeyFile)
	case RoleExecutor:
		requireFile("EXECUTOR_DISPATCH_PUBLIC_KEY_FILE", c.Enforcement.ExecutorDispatchPublicKeyFile)
		requireFile("EXECUTOR_RESULT_PRIVATE_KEY_FILE", c.Enforcement.ExecutorResultPrivateKeyFile)
		if c.Enforcement.NFTBinaryExpectedSHA256 == "" {
			l.fail("NFT_BINARY_EXPECTED_SHA256", "is required for service role executor")
		}
		if c.Enforcement.NFTExpectedVersion == "" {
			l.fail("NFT_EXPECTED_VERSION", "is required for service role executor")
		}
	case RoleSimulator:
		requireSecret("AUTH_EVENT_HMAC_KEY", c.Events.AuthHMACKey)
		requireSecret("AUTH_ACCOUNT_HASH_KEY", c.Events.AuthAccountHashKey)
		requireFile("DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE", c.Demo.HistorySimulatorPrivateKeyFile)
	case RoleDemoApp:
		requireSecret("AUTH_EVENT_HMAC_KEY", c.Events.AuthHMACKey)
		requireSecret("AUTH_ACCOUNT_HASH_KEY", c.Events.AuthAccountHashKey)
	case RoleMigrator:
		requireSecret("DATABASE_MIGRATION_URL", c.Database.MigrationURL)
	case RoleReader:
		requireSecret("DATABASE_READ_URL", c.Database.ReadURL)
	}
}

func forbiddenDetectorSecret(lookup LookupFunc) string {
	// The always-on deterministic detector gets one least-privilege database
	// credential and no model, ingestion, administrator, signing, or execution
	// authority. Reject inherited credentials before any parser copies them into
	// the returned Config.
	for _, name := range []string{
		"DATABASE_MIGRATION_URL",
		"DATABASE_API_URL",
		"DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL",
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"OPENAI_API_KEY",
		"ADMIN_PASSWORD_ARGON2ID_HASH",
		"SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY",
		"AUTH_EVENT_HMAC_KEY",
		"AUTH_ACCOUNT_HASH_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"DISPATCHER_RESULT_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return name
		}
	}
	return ""
}

func forbiddenDemoRuntimeAuthority(lookup LookupFunc) string {
	// Import and activation are one-shot commands outside the generic service
	// configuration loader. Only the analysis and validation consumers may
	// receive public proof inputs plus their own consumer-specific capability;
	// every other service rejects the complete ambient handoff surface.
	for _, name := range []string{
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return name
		}
	}
	return ""
}

func forbiddenValidatorSecret(lookup LookupFunc) string {
	// Reject a broad inherited environment before any credential parser copies
	// values into a Config. The validator is intentionally credentialless.
	for _, name := range []string{
		"DATABASE_MIGRATION_URL",
		"DATABASE_API_URL",
		"DATABASE_WORKER_URL",
		"DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL",
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"OPENAI_API_KEY",
		"ADMIN_PASSWORD_ARGON2ID_HASH",
		"SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY",
		"AUTH_EVENT_HMAC_KEY",
		"AUTH_ACCOUNT_HASH_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"DISPATCHER_RESULT_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return name
		}
	}
	return ""
}

func forbiddenAnalysisWorkerAuthority(lookup LookupFunc) string {
	// The OpenAI analysis worker receives one least-privilege database URL and
	// its bounded OpenAI configuration plus, in the isolated demo environment
	// only, the public signed-history proof. Validation, ingestion,
	// administrator, dispatcher, executor, private demo-history authority, and
	// libpq inheritance are rejected before any parser can copy them into the
	// returned Config.
	environment, _ := lookup("SENTINELFLOW_ENV")
	if environment != string(EnvironmentDemo) {
		for _, name := range []string{
			"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
			"DEMO_HISTORY_PUBLIC_KEY_B64URL",
			"DEMO_HISTORY_RUN_SCOPE",
			"DEMO_HISTORY_IMPORT_ID",
			"DEMO_HISTORY_CLOCK_AT",
			"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
			"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
			"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
		} {
			if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
				return name
			}
		}
	}
	for _, name := range []string{
		"DATABASE_MIGRATION_URL",
		"DATABASE_API_URL",
		"DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL",
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"INTERNAL_GATEWAY_INGEST_URL",
		"INTERNAL_AUTH_INGEST_URL",
		"GATEWAY_EVENT_SENDER_ID",
		"GATEWAY_EVENT_HMAC_KEY_ID",
		"ADMIN_USERNAME",
		"ADMIN_PASSWORD_ARGON2ID_HASH",
		"ADMIN_ALLOWED_ORIGINS",
		"ADMIN_SESSION_COOKIE_NAME",
		"ADMIN_COOKIE_TRANSPORT",
		"SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY",
		"GATEWAY_EXPECTED_SOURCE_BINDING_ID",
		"GATEWAY_SOURCE_CONFIG_SHA256",
		"AUTH_EVENT_SENDER_ID",
		"AUTH_EVENT_SERVICE_LABEL",
		"AUTH_EVENT_HMAC_KEY_ID",
		"AUTH_EVENT_HMAC_KEY",
		"AUTH_EXPECTED_SOURCE_BINDING_ID",
		"AUTH_SOURCE_CONFIG_SHA256",
		"AUTH_ACCOUNT_HASH_KEY",
		"AUTH_EVENT_SENDER_CHECKPOINT_FILE",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"DISPATCHER_RESULT_PUBLIC_KEY_FILE",
		"DISPATCH_CAPABILITY_TTL",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"EXECUTOR_SOCKET",
		"EXECUTOR_REPLAY_JOURNAL",
		"EXECUTOR_STARTUP_MODE",
		"EXECUTOR_MAX_FRAME_BYTES",
		"EXECUTOR_IO_TIMEOUT",
		"NFT_BINARY",
		"NFT_BINARY_EXPECTED_SHA256",
		"NFT_EXPECTED_VERSION",
		"NFT_VALIDATOR_SOCKET",
		"NFT_FAMILY",
		"NFT_TABLE",
		"NFT_BLACKLIST_SET",
		"NFT_INPUT_CHAIN",
		"NFT_PROTECTED_TCP_PORT",
		"NFT_INPUT_PRIORITY",
		"NFT_BASE_CHAIN_SCHEMA_VERSION",
		"NFT_BASE_CHAIN_CONTRACT",
		"NFT_BASE_CHAIN_EXPECTED_SHA256",
		"NFT_BASE_CHAIN_LIVE_CONTRACT",
		"NFT_BASE_CHAIN_LIVE_EXPECTED_SHA256",
		"PROTECTED_IPV4_CONTRACT",
		"PROTECTED_IPV4_EXPECTED_SHA256",
		"PROTECTED_CIDRS",
		"PROTECTED_ORIGIN_IPV4",
		"PROTECTED_GATEWAY_IPV4",
		"PROTECTED_EXECUTOR_IPV4",
		"PROTECTED_MANAGEMENT_IPV4",
		"PROTECTED_CURRENT_ADMIN_IPV4",
		"HOST_ENFORCEMENT_ENABLED",
		"BLOCK_TTL_MIN",
		"BLOCK_TTL_DEFAULT",
		"BLOCK_TTL_MAX",
		"VALIDATION_TTL",
		"APPROVAL_TTL",
		"HISTORICAL_IMPACT_LOOKBACK",
		"DEMO_ALLOW_RFC5737",
		"DEMO_ENFORCEMENT_ISOLATION_VERIFIED",
		"DEMO_HOST_RULESET_UNCHANGED",
		"DEMO_HISTORY_FIXTURE_DATASET",
		"DEMO_HISTORY_DATASET_EXPECTED_SHA256",
		"DEMO_HISTORY_FIXTURE_MANIFEST",
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_PRIVATE_KEY",
		"DEMO_HISTORY_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNING_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
		"HIL_REAUTH_AFTER",
		"HIL_CHALLENGE_TTL",
		"HIL_DECISION_RATE_LIMIT_PER_MINUTE",
		"ADMIN_LOGIN_RATE_LIMIT_PER_SOURCE_PER_MINUTE",
		"ADMIN_LOGIN_RATE_LIMIT_GLOBAL_PER_MINUTE",
		"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGAPPNAME", "PGSSLMODE", "PGSSLROOTCERT",
		"PGSSLCERT", "PGSSLKEY", "PGTARGETSESSIONATTRS",
	} {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return name
		}
	}
	return ""
}

func forbiddenValidationWorkerAuthority(lookup LookupFunc) string {
	// Policy validation receives public contract/history assertions, one worker
	// database URL, and the isolated validator's public attestation inputs. It
	// must never inherit model, ingestion, administrator, signing, dispatcher,
	// executor, simulator, private-key, or libpq authority.
	environment, _ := lookup("SENTINELFLOW_ENV")
	if environment != string(EnvironmentDemo) {
		for _, name := range []string{
			"DEMO_HISTORY_SIGNED_ENVELOPE_FILE", "DEMO_HISTORY_PUBLIC_KEY_B64URL",
			"DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID", "DEMO_HISTORY_CLOCK_AT",
			"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST", "DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
			"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
		} {
			if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
				return name
			}
		}
	}
	for _, name := range []string{
		"DATABASE_MIGRATION_URL", "DATABASE_API_URL", "DATABASE_READ_URL", "DATABASE_DISPATCHER_URL",
		"DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL",
		"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_MODEL", "OPENAI_REASONING_EFFORT",
		"OPENAI_STORE", "OPENAI_INPUT_SCHEMA_FILE", "OPENAI_SYSTEM_PROMPT_FILE", "OPENAI_OUTPUT_SCHEMA_FILE",
		"OPENAI_MAX_EVIDENCE_REFS", "OPENAI_MAX_INPUT_BYTES", "OPENAI_MAX_OUTPUT_TOKENS", "OPENAI_TIMEOUT",
		"OPENAI_MAX_TRANSIENT_RETRIES", "OPENAI_MAX_CONCURRENCY", "OPENAI_DAILY_BUDGET_USD",
		"OPENAI_RATE_CARD_VERSION", "OPENAI_INPUT_USD_PER_1M_TOKENS",
		"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS", "OPENAI_OUTPUT_USD_PER_1M_TOKENS", "OPENAI_BUDGET_TIMEZONE",
		"ADMIN_USERNAME", "ADMIN_PASSWORD_ARGON2ID_HASH", "ADMIN_ALLOWED_ORIGINS", "ADMIN_SESSION_COOKIE_NAME",
		"ADMIN_COOKIE_TRANSPORT", "SESSION_HMAC_KEY", "SESSION_TTL", "SESSION_IDLE_TIMEOUT",
		"HIL_REAUTH_AFTER", "HIL_CHALLENGE_TTL", "HIL_DECISION_RATE_LIMIT_PER_MINUTE",
		"ADMIN_LOGIN_RATE_LIMIT_PER_SOURCE_PER_MINUTE", "ADMIN_LOGIN_RATE_LIMIT_GLOBAL_PER_MINUTE",
		"INTERNAL_GATEWAY_INGEST_URL", "INTERNAL_AUTH_INGEST_URL", "GATEWAY_EVENT_SENDER_ID",
		"GATEWAY_EVENT_HMAC_KEY_ID", "GATEWAY_EVENT_HMAC_KEY", "GATEWAY_EXPECTED_SOURCE_BINDING_ID",
		"GATEWAY_SOURCE_CONFIG_SHA256", "AUTH_EVENT_SENDER_ID", "AUTH_EVENT_SERVICE_LABEL", "AUTH_EVENT_HMAC_KEY_ID",
		"AUTH_EVENT_HMAC_KEY", "AUTH_EXPECTED_SOURCE_BINDING_ID", "AUTH_SOURCE_CONFIG_SHA256",
		"AUTH_ACCOUNT_HASH_KEY", "AUTH_EVENT_SENDER_CHECKPOINT_FILE", "AUTH_EVENT_BINDING_TIMEOUT",
		"EVENT_MAX_FUTURE_SKEW", "EVENT_MAX_PAST_SKEW",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE", "DISPATCHER_RESULT_PUBLIC_KEY_FILE", "DISPATCH_CAPABILITY_TTL",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE", "EXECUTOR_RESULT_PRIVATE_KEY_FILE", "EXECUTOR_SOCKET",
		"EXECUTOR_STARTUP_MODE", "EXECUTOR_IO_TIMEOUT", "EXECUTOR_MAX_FRAME_BYTES", "EXECUTOR_REPLAY_JOURNAL",
		"NFT_BINARY", "NFT_FAMILY", "NFT_TABLE", "NFT_BLACKLIST_SET", "NFT_INPUT_CHAIN",
		"NFT_PROTECTED_TCP_PORT", "NFT_INPUT_PRIORITY", "HOST_ENFORCEMENT_ENABLED",
		"BLOCK_TTL_MIN", "BLOCK_TTL_DEFAULT", "BLOCK_TTL_MAX", "APPROVAL_TTL",
		"DEMO_HISTORY_FIXTURE_DATASET", "DEMO_HISTORY_DATASET_EXPECTED_SHA256",
		"DEMO_HISTORY_FIXTURE_MANIFEST", "DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE", "DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE", "DEMO_HISTORY_PRIVATE_KEY", "DEMO_HISTORY_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNING_PRIVATE_KEY_FILE", "DEMO_HISTORY_SIGNER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_TEST_CLOCK", "CONTRACT_VECTOR_BUNDLE",
		"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGAPPNAME", "PGSSLMODE", "PGSSLROOTCERT",
		"PGSSLCERT", "PGSSLKEY", "PGTARGETSESSIONATTRS",
	} {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return name
		}
	}
	return ""
}
