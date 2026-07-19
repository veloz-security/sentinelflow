// Package config loads SentinelFlow's immutable startup configuration.
package config

import (
	"net/netip"
	"net/url"
	"os"
	"time"
)

type Role string

const (
	RoleGateway          Role = "gateway"
	RoleAPI              Role = "api"
	RoleDetector         Role = "detector"
	RoleWorker           Role = "worker"
	RoleValidationWorker Role = "validation-worker"
	RoleValidator        Role = "validator"
	RoleDispatcher       Role = "dispatcher"
	RoleExecutor         Role = "executor"
	RoleSimulator        Role = "simulator"
	RoleDemoApp          Role = "demo-app"
	RoleMigrator         Role = "migrator"
	RoleReader           Role = "reader"
)

const (
	DemoHistoryAnalysisActivationPath   = "/run/secrets/sentinelflow-demo-history-analysis/activation-capability"
	DemoHistoryValidationActivationPath = "/run/secrets/sentinelflow-demo-history-validation/activation-capability"
)

func (r Role) Valid() bool {
	switch r {
	case RoleGateway, RoleAPI, RoleDetector, RoleWorker, RoleValidationWorker, RoleValidator, RoleDispatcher, RoleExecutor, RoleSimulator, RoleDemoApp, RoleMigrator, RoleReader:
		return true
	default:
		return false
	}
}

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentDemo        Environment = "demo"
	EnvironmentProduction  Environment = "production"
)

type ExecutorStartupMode string

const (
	ExecutorStartupVerify    ExecutorStartupMode = "verify"
	ExecutorStartupBootstrap ExecutorStartupMode = "bootstrap"
)

type AdminCookieTransport string

const (
	AdminCookieTransportTLS       AdminCookieTransport = "tls"
	AdminCookieTransportLocalTest AdminCookieTransport = "explicit-local-test"
)

type Config struct {
	Role        Role
	Environment Environment
	Gateway     GatewayConfig
	Listeners   ListenerConfig
	Events      EventConfig
	Database    DatabaseConfig
	OpenAI      OpenAIConfig
	Admin       AdminConfig
	Detection   DetectionConfig
	Incidents   IncidentConfig
	Enforcement EnforcementConfig
	Demo        DemoConfig
	Retention   RetentionConfig
}

type GatewayConfig struct {
	ServiceLabel               string
	ListenAddr                 string
	MetricsListenAddr          string
	PublicHost                 string
	UpstreamURL                url.URL
	UpstreamHost               string
	OriginCIDRs                []netip.Prefix
	MaxHeaderBytes             int
	MaxRequestTargetBytes      int
	MaxClassificationPathBytes int
	MaxBodyBytes               int64
	HeaderReadTimeout          time.Duration
	RequestTimeout             time.Duration
	UpstreamTimeout            time.Duration
	IdleTimeout                time.Duration
	EventQueueCapacity         int
	EventBatchSize             int
	EventMaxBatchBytes         int
	EventFlushInterval         time.Duration
	SenderCheckpointFile       string
	TLSCertFile                string
	TLSKeyFile                 string
	PathCatalogVersion         string
	AuthRoutePath              string
	AuthRouteLabel             string
}

type ListenerConfig struct {
	DemoOriginHTTPAddr       string
	InternalAPIIngestAddr    string
	APIManagementAddr        string
	APIManagementPublishHost netip.Addr
}

type EventConfig struct {
	GatewayIngestURL        url.URL
	AuthIngestURL           url.URL
	GatewaySenderID         string
	GatewayHMACKeyID        string
	GatewayHMACKey          Secret
	GatewaySourceBindingID  string
	GatewaySourceConfigHash string
	AuthSenderID            string
	AuthServiceLabel        string
	AuthHMACKeyID           string
	AuthHMACKey             Secret
	AuthSourceBindingID     string
	AuthSourceConfigHash    string
	AuthAccountHashKey      Secret
	AuthCheckpointFile      string
	AuthBindingTimeout      time.Duration
	MaxFutureSkew           time.Duration
	MaxPastSkew             time.Duration
}

type DatabaseConfig struct {
	MigrationURL  Secret
	APIURL        Secret
	WorkerURL     Secret
	ReadURL       Secret
	DispatcherURL Secret
}

type OpenAIConfig struct {
	APIKey                   Secret
	Model                    string
	ReasoningEffort          string
	Store                    bool
	InputSchemaFile          string
	SystemPromptFile         string
	OutputSchemaFile         string
	MaxEvidenceRefs          int
	MaxInputBytes            int
	MaxOutputTokens          int
	Timeout                  time.Duration
	MaxTransientRetries      int
	MaxConcurrency           int
	DailyBudgetUSD           float64
	RateCardVersion          string
	InputUSDPerMillion       float64
	CachedInputUSDPerMillion float64
	OutputUSDPerMillion      float64
	BudgetTimezone           string
}

type AdminConfig struct {
	Username                string
	PasswordArgon2idHash    Secret
	SessionHMACKey          Secret
	AllowedOrigins          []string
	SessionCookieName       string
	CookieTransport         AdminCookieTransport
	SessionTTL              time.Duration
	SessionIdleTimeout      time.Duration
	HILReauthAfter          time.Duration
	HILChallengeTTL         time.Duration
	HILDecisionsPerMinute   int
	LoginPerSourcePerMinute int
	LoginGlobalPerMinute    int
}

type DetectionConfig struct {
	PathScanUniquePaths              int
	PathScanWindow                   time.Duration
	SuspiciousPathIDs                []string
	RequestBurstCount                int
	RequestBurstWindow               time.Duration
	BruteForceFailures               int
	BruteForceWindow                 time.Duration
	CredentialStuffingFailures       int
	CredentialStuffingUniqueAccounts int
	CredentialStuffingWindow         time.Duration
}

type IncidentConfig struct {
	CorrelationWindow time.Duration
	CloseAfter        time.Duration
	ReopenWithin      time.Duration
}

type EnforcementConfig struct {
	NFTBinary                     string
	NFTBinaryExpectedSHA256       string
	NFTExpectedVersion            string
	NFTFamily                     string
	NFTTable                      string
	NFTBlacklistSet               string
	NFTInputChain                 string
	NFTProtectedTCPPort           int
	NFTInputPriority              int
	BaseChainSchemaVersion        string
	BaseChainContract             string
	BaseChainExpectedSHA256       string
	BaseChainLiveContract         string
	BaseChainLiveExpectedSHA256   string
	ValidatorSocket               string
	ExecutorSocket                string
	ExecutorReplayJournal         string
	ExecutorStartupMode           ExecutorStartupMode
	ExecutorMaxFrameBytes         int
	ExecutorIOTimeout             time.Duration
	DispatchCapabilityTTL         time.Duration
	DispatcherSigningKeyFile      string
	ExecutorDispatchPublicKeyFile string
	ExecutorResultPrivateKeyFile  string
	DispatcherResultPublicKeyFile string
	BlockTTLMin                   time.Duration
	BlockTTLDefault               time.Duration
	BlockTTLMax                   time.Duration
	ValidationTTL                 time.Duration
	ApprovalTTL                   time.Duration
	HistoricalImpactLookback      time.Duration
	ProtectedIPv4Contract         string
	ProtectedIPv4ExpectedSHA256   string
	ProtectedCIDRs                []netip.Prefix
	ProtectedOriginIPv4           []netip.Addr
	ProtectedGatewayIPv4          []netip.Addr
	ProtectedExecutorIPv4         []netip.Addr
	ProtectedManagementIPv4       []netip.Addr
	ProtectedCurrentAdminIPv4     []netip.Addr
	HostEnforcementEnabled        bool
}

type DemoConfig struct {
	GatewayPeerCIDRs                      []netip.Prefix
	AllowRFC5737                          bool
	EnforcementIsolationVerified          bool
	HostRulesetUnchanged                  bool
	ClientCIDR                            netip.Prefix
	AttackSourceIP                        netip.Addr
	TestClock                             time.Time
	HistoryFixtureDataset                 string
	HistoryDatasetExpectedSHA256          string
	HistoryFixtureManifest                string
	HistoryImportID                       string
	ContractVectorBundle                  string
	HistoryPublicKeyFile                  string
	HistorySimulatorPrivateKeyFile        string
	HistorySignedEnvelopeFile             string
	HistoryAnalysisActivationSecretFile   string
	HistoryValidationActivationSecretFile string
	HistoryPublicKeyB64URL                string
	HistoryRunScope                       string
	HistoryClockAt                        time.Time
	HistoryImpactSourceHealthDigest       string
}

type RetentionConfig struct {
	EventEvidence    time.Duration
	IncidentAIPolicy time.Duration
	Audit            time.Duration
}

type LookupFunc func(string) (string, bool)

func Load(role Role) (Config, error) {
	return LoadFrom(role, os.LookupEnv)
}

func LoadFrom(role Role, lookup LookupFunc) (Config, error) {
	if !role.Valid() {
		return Config{}, configError("ROLE", "unsupported service role")
	}
	if lookup == nil {
		return Config{}, configError("ENVIRONMENT", "lookup function is nil")
	}
	if role != RoleWorker && role != RoleValidationWorker {
		if name := forbiddenDemoRuntimeAuthority(lookup); name != "" {
			return Config{}, configError(name, "must not be provided to this service role")
		}
	}
	if role == RoleValidator {
		if name := forbiddenValidatorSecret(lookup); name != "" {
			return Config{}, configError(name, "must not be provided to service role validator")
		}
	}
	if role == RoleWorker {
		if name := forbiddenAnalysisWorkerAuthority(lookup); name != "" {
			return Config{}, configError(name, "must not be provided to service role worker")
		}
	}
	if role == RoleValidationWorker {
		if name := forbiddenValidationWorkerAuthority(lookup); name != "" {
			return Config{}, configError(name, "must not be provided to service role validation-worker")
		}
	}
	if role == RoleDetector {
		if name := forbiddenDetectorSecret(lookup); name != "" {
			return Config{}, configError(name, "must not be provided to service role detector")
		}
	}

	l := newLoader(lookup)
	c := Config{Role: role}
	c.Environment = Environment(l.enum("SENTINELFLOW_ENV", "development", "development", "test", "demo", "production"))

	c.Gateway = loadGateway(l)
	c.Listeners = loadListeners(l)
	c.Events = loadEvents(l)
	c.Database = loadDatabase(l)
	c.OpenAI = loadOpenAI(l)
	c.Admin = loadAdmin(l)
	c.Detection = loadDetection(l)
	c.Incidents = loadIncidents(l)
	c.Enforcement = loadEnforcement(l)
	c.Demo = loadDemo(l)
	c.Retention = loadRetention(l)

	validateCrossFields(l, &c)
	validateRequiredSecrets(l, &c)
	if l.err != nil {
		return Config{}, l.err
	}
	return c, nil
}
