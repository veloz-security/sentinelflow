// Command democonfig creates one local, ignored SentinelFlow demo credential
// bundle. It never prints credential values and refuses to overwrite an
// existing bundle.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/demohistoryimport"
	"github.com/devwooops/sentinelflow/internal/demohistoryseal"
	"golang.org/x/crypto/argon2"
)

const (
	defaultEnvironmentFile                = ".env.demo"
	defaultSecretsDirectory               = "secrets/demo"
	defaultHistoryDirectory               = "data/demo-history"
	adminPasswordVariable                 = "SENTINELFLOW_ADMIN_PASSWORD"
	nftDigestVariable                     = "SENTINELFLOW_NFT_BINARY_SHA256"
	nftVersionVariable                    = "SENTINELFLOW_NFT_VERSION"
	minimumPasswordBytes                  = 16
	maximumPasswordBytes                  = 128
	secretBytes                           = 32
	argonMemoryKiB                        = 65536
	argonIterations                       = 3
	argonParallelism                      = 2
	keyIdentityDigestBytes                = 24
	demoDatasetContainerPath              = "/app/contracts/fixtures/demo_history_dataset_v1.json"
	demoEnvelopeContainerPath             = "/run/sentinelflow-demo-history/signed-manifest.json"
	demoAnalysisActivationContainerPath   = "/run/secrets/sentinelflow-demo-history-analysis/activation-capability"
	demoValidationActivationContainerPath = "/run/secrets/sentinelflow-demo-history-validation/activation-capability"

	gatewayProducerConfigV1 = "sentinelflow-source-producer-config-v1\n" +
		"batch_size=100\n" +
		"checkpoint_path=/var/lib/sentinelflow-gateway/sender-state.json\n" +
		"endpoint_kind=gateway\n" +
		"endpoint_path=/internal/v1/gateway-events\n" +
		"flush_interval=100ms\n" +
		"max_batch_bytes=262144\n" +
		"queue_capacity=10000\n" +
		"record_schemas=gateway-http-v1,source-coverage-v1,source-health-v1\n" +
		"sender_id=gateway-01\n" +
		"service_label=demo-app\n"
	authProducerConfigV1 = "sentinelflow-source-producer-config-v1\n" +
		"binding_timeout=5m\n" +
		"checkpoint_path=/var/lib/sentinelflow-auth-adapter/sender-state.json\n" +
		"endpoint_kind=auth\n" +
		"endpoint_path=/internal/v1/auth-events\n" +
		"record_schemas=auth-event-v1,source-coverage-v1,source-health-v1\n" +
		"sender_id=demo-app\n" +
		"service_label=demo-app\n"
)

type options struct {
	environmentFile  string
	secretsDirectory string
	historyDirectory string
	repositoryRoot   string
	adminUsername    string
	adminPassword    []byte
	nftBinarySHA256  string
	nftVersion       string
	now              time.Time
}

var (
	nftDigestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nftVersionPattern      = regexp.MustCompile(`^nftables v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	keyIdentityPrefix      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,14}$`)
	canonicalUUIDv4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type generatedValues struct {
	environment          []byte
	credentials          []byte
	analysisActivation   []byte
	validationActivation []byte
	dispatchPrivate      []byte
	dispatchPublic       []byte
	resultPrivate        []byte
	resultPublic         []byte
	historyEnvelope      []byte
	historyAssertions    []byte
}

type credentialsFile struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	GeneratedAt string `json:"generated_at"`
}

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow demo configuration failed:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, output io.Writer) error {
	flags := flag.NewFlagSet("democonfig", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	environmentFile := flags.String("output", defaultEnvironmentFile, "ignored Compose environment file")
	secretsDirectory := flags.String("secrets-dir", defaultSecretsDirectory, "ignored local secret directory")
	historyDirectory := flags.String("history-dir", defaultHistoryDirectory, "ignored public demo-history authority directory")
	adminUsername := flags.String("admin-username", "admin", "local administrator username")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid arguments")
	}
	password := []byte(getenv(adminPasswordVariable))
	if len(password) == 0 {
		generated, err := randomText(24)
		if err != nil {
			return errors.New("could not generate administrator credential")
		}
		password = []byte(generated)
	}
	defer clear(password)
	repositoryRoot, err := os.Getwd()
	if err != nil {
		return errors.New("could not resolve repository root")
	}
	repositoryRoot, err = filepath.Abs(repositoryRoot)
	if err != nil {
		return errors.New("could not resolve repository root")
	}
	if err := generate(options{
		environmentFile:  *environmentFile,
		secretsDirectory: *secretsDirectory,
		historyDirectory: *historyDirectory,
		repositoryRoot:   repositoryRoot,
		adminUsername:    *adminUsername,
		adminPassword:    password,
		nftBinarySHA256:  getenv(nftDigestVariable),
		nftVersion:       getenv(nftVersionVariable),
		now:              time.Now().UTC(),
	}); err != nil {
		return err
	}
	if output != nil {
		_, _ = fmt.Fprintf(output, "created ignored demo configuration at %s; credentials are stored under %s; public history authority is stored under %s\n", *environmentFile, *secretsDirectory, *historyDirectory)
	}
	return nil
}

func generate(input options) error {
	if err := validateOptions(input); err != nil {
		return err
	}
	if _, err := os.Lstat(input.environmentFile); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("environment output already exists or is not safely inspectable")
	}
	if _, err := os.Lstat(input.secretsDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("secret output already exists or is not safely inspectable")
	}
	if _, err := os.Lstat(input.historyDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("history output already exists or is not safely inspectable")
	}
	values, err := buildValues(input)
	if err != nil {
		return err
	}
	defer values.clear()

	if err = os.MkdirAll(filepath.Dir(input.environmentFile), 0o750); err != nil {
		return errors.New("could not prepare environment output parent")
	}
	if err = os.MkdirAll(filepath.Dir(input.secretsDirectory), 0o700); err != nil {
		return errors.New("could not prepare secret output parent")
	}
	if err = os.MkdirAll(filepath.Dir(input.historyDirectory), 0o755); err != nil {
		return errors.New("could not prepare history output parent")
	}
	if err = os.Mkdir(input.secretsDirectory, 0o700); err != nil {
		return errors.New("could not create secret output")
	}
	if err = os.Chmod(input.secretsDirectory, 0o700); err != nil {
		_ = os.RemoveAll(input.secretsDirectory)
		return errors.New("could not secure secret output")
	}
	if err = os.Mkdir(input.historyDirectory, 0o755); err != nil {
		_ = os.RemoveAll(input.secretsDirectory)
		return errors.New("could not create history output")
	}
	if err = os.Chmod(input.historyDirectory, 0o755); err != nil {
		_ = os.RemoveAll(input.secretsDirectory)
		_ = os.RemoveAll(input.historyDirectory)
		return errors.New("could not set public history output mode")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(input.secretsDirectory)
			_ = os.RemoveAll(input.historyDirectory)
			_ = os.Remove(input.environmentFile)
		}
	}()
	files := []struct {
		name     string
		contents []byte
		mode     os.FileMode
	}{
		{"admin-credentials.json", values.credentials, 0o600},
		{"demo-history-analysis-activation.capability", values.analysisActivation, 0o400},
		{"demo-history-validation-activation.capability", values.validationActivation, 0o400},
		{"dispatcher-capability-private.pem", values.dispatchPrivate, 0o600},
		{"dispatcher-capability-public.pem", values.dispatchPublic, 0o644},
		{"executor-result-private.pem", values.resultPrivate, 0o600},
		{"executor-result-public.pem", values.resultPublic, 0o644},
	}
	for _, file := range files {
		if err = writeExclusive(filepath.Join(input.secretsDirectory, file.name), file.contents, file.mode); err != nil {
			return errors.New("could not write local secret bundle")
		}
	}
	publicFiles := []struct {
		name     string
		contents []byte
	}{
		{demohistoryseal.EnvelopeFileName, values.historyEnvelope},
		{demohistoryseal.AssertionsFileName, values.historyAssertions},
	}
	for _, file := range publicFiles {
		if err = writeExclusive(filepath.Join(input.historyDirectory, file.name), file.contents, 0o444); err != nil {
			return errors.New("could not write public demo history authority")
		}
	}
	if err = writeExclusive(input.environmentFile, values.environment, 0o600); err != nil {
		return errors.New("could not write local environment bundle")
	}
	cleanup = false
	return nil
}

func validateOptions(input options) error {
	if input.environmentFile == "" || input.secretsDirectory == "" || input.historyDirectory == "" ||
		input.repositoryRoot == "" || !filepath.IsAbs(input.repositoryRoot) || input.now.IsZero() ||
		filepath.Clean(input.environmentFile) != input.environmentFile ||
		filepath.Clean(input.secretsDirectory) != input.secretsDirectory ||
		filepath.Clean(input.historyDirectory) != input.historyDirectory ||
		filepath.Clean(input.repositoryRoot) != input.repositoryRoot ||
		input.environmentFile == input.secretsDirectory || input.environmentFile == input.historyDirectory ||
		input.secretsDirectory == input.historyDirectory || strings.ContainsRune(input.environmentFile, 0) ||
		strings.ContainsRune(input.secretsDirectory, 0) || strings.ContainsRune(input.historyDirectory, 0) {
		return errors.New("invalid output configuration")
	}
	if !validIdentity(input.adminUsername) || !validPassword(input.adminPassword) {
		return errors.New("invalid administrator credential input")
	}
	if !nftDigestPattern.MatchString(input.nftBinarySHA256) || !nftVersionPattern.MatchString(input.nftVersion) {
		return errors.New("invalid nftables attestation input")
	}
	return nil
}

func validIdentity(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, current := range value {
		if !(current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' ||
			current >= '0' && current <= '9' || strings.ContainsRune("-_.@", current)) {
			return false
		}
	}
	return true
}

func validPassword(value []byte) bool {
	if len(value) < minimumPasswordBytes || len(value) > maximumPasswordBytes {
		return false
	}
	for _, current := range value {
		if current < 0x20 || current > 0x7e {
			return false
		}
	}
	return true
}

func buildValues(input options) (generatedValues, error) {
	var result generatedValues
	reader, err := demohistoryimport.NewFixedDatasetFile(input.repositoryRoot)
	if err != nil {
		return result, errors.New("could not configure fixed demo history dataset")
	}
	rawDataset, err := reader.ReadPinnedDataset(context.Background())
	if err != nil {
		return result, errors.New("could not read fixed demo history dataset")
	}
	historyBundle, err := demohistoryseal.Seal(context.Background(), rawDataset, rand.Reader)
	clear(rawDataset)
	if err != nil {
		return result, errors.New("could not create run-scoped demo history authority")
	}
	result.historyEnvelope = historyBundle.SignedEnvelope()
	result.historyAssertions = historyBundle.PublicAssertions()
	historyAssertions, err := demohistoryseal.ParseAssertions(result.historyAssertions)
	if err != nil {
		return generatedValues{}, errors.New("could not parse run-scoped demo history authority")
	}
	passwordHash, err := passwordPHC(input.adminPassword)
	if err != nil {
		return result, errors.New("could not derive administrator verifier")
	}
	gatewayKey, err := randomBase64(secretBytes)
	if err != nil {
		return result, errors.New("could not generate event credentials")
	}
	authKey, err := randomBase64(secretBytes)
	if err != nil {
		return result, errors.New("could not generate event credentials")
	}
	gatewayKeyID, err := eventKeyID("gateway-key", gatewayKey)
	if err != nil {
		return result, errors.New("could not derive event key identity")
	}
	authKeyID, err := eventKeyID("auth-key", authKey)
	if err != nil {
		return result, errors.New("could not derive event key identity")
	}
	gatewayBindingID, err := randomUUIDv4()
	if err != nil {
		return result, errors.New("could not generate source binding identity")
	}
	authBindingID, err := randomUUIDv4()
	if err != nil {
		return result, errors.New("could not generate source binding identity")
	}
	accountKey, err := randomBase64(secretBytes)
	if err != nil {
		return result, errors.New("could not generate event credentials")
	}
	sessionKey, err := randomBase64(secretBytes)
	if err != nil {
		return result, errors.New("could not generate session credential")
	}
	postgresPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	apiPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	workerPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	readPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	dispatcherPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	retentionPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	lifecyclePassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	metricsPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	demoImporterPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	demoActivatorPassword, err := randomText(32)
	if err != nil {
		return result, errors.New("could not generate database credentials")
	}
	result.analysisActivation, err = randomSecret(secretBytes)
	if err != nil {
		return result, errors.New("could not generate demo-history activation capability")
	}
	result.validationActivation, err = randomSecret(secretBytes)
	if err != nil {
		return result, errors.New("could not generate demo-history activation capability")
	}
	for bytes.Equal(result.analysisActivation, result.validationActivation) {
		clear(result.validationActivation)
		result.validationActivation, err = randomSecret(secretBytes)
		if err != nil {
			return result, errors.New("could not generate distinct demo-history activation capabilities")
		}
	}

	dispatchPublic, dispatchPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return result, errors.New("could not generate dispatcher key")
	}
	defer clear(dispatchPrivate)
	resultPublic, resultPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return result, errors.New("could not generate executor key")
	}
	defer clear(resultPrivate)
	result.dispatchPrivate, err = privatePEM(dispatchPrivate)
	if err != nil {
		return generatedValues{}, errors.New("could not encode dispatcher key")
	}
	result.dispatchPublic, err = publicPEM(dispatchPublic)
	if err != nil {
		return generatedValues{}, errors.New("could not encode dispatcher key")
	}
	result.resultPrivate, err = privatePEM(resultPrivate)
	if err != nil {
		return generatedValues{}, errors.New("could not encode executor key")
	}
	result.resultPublic, err = publicPEM(resultPublic)
	if err != nil {
		return generatedValues{}, errors.New("could not encode executor key")
	}

	credentialDocument := credentialsFile{
		Username:    input.adminUsername,
		Password:    string(input.adminPassword),
		GeneratedAt: input.now.Format(time.RFC3339),
	}
	result.credentials, err = json.MarshalIndent(credentialDocument, "", "  ")
	if err != nil {
		return generatedValues{}, errors.New("could not encode administrator credentials")
	}
	result.credentials = append(result.credentials, '\n')

	values := [][2]string{
		{"COMPOSE_PROJECT_NAME", "sentinelflow"},
		{"COMPOSE_PROFILES", "stub-ai"},
		{"POSTGRES_DB", "sentinelflow"},
		{"POSTGRES_USER", "postgres"},
		{"POSTGRES_PASSWORD", postgresPassword},
		{"DATABASE_API_PASSWORD", apiPassword},
		{"DATABASE_WORKER_PASSWORD", workerPassword},
		{"DATABASE_READ_PASSWORD", readPassword},
		{"DATABASE_DISPATCHER_PASSWORD", dispatcherPassword},
		{"DATABASE_RETENTION_PASSWORD", retentionPassword},
		{"DATABASE_LIFECYCLE_PASSWORD", lifecyclePassword},
		{"DATABASE_METRICS_PASSWORD", metricsPassword},
		{"DATABASE_DEMO_IMPORTER_PASSWORD", demoImporterPassword},
		{"DATABASE_DEMO_ACTIVATOR_PASSWORD", demoActivatorPassword},
		{"DATABASE_API_URL", databaseURL("sentinelflow_api", apiPassword)},
		{"DATABASE_WORKER_URL", databaseURL("sentinelflow_worker", workerPassword)},
		{"DATABASE_READ_URL", databaseURL("sentinelflow_read", readPassword)},
		{"DATABASE_DISPATCHER_URL", databaseURL("sentinelflow_dispatcher", dispatcherPassword)},
		{"DATABASE_RETENTION_URL", databaseURL("sentinelflow_retention", retentionPassword)},
		{"DATABASE_LIFECYCLE_URL", databaseURL("sentinelflow_lifecycle", lifecyclePassword)},
		{"DATABASE_METRICS_URL", databaseURL("sentinelflow_metrics", metricsPassword)},
		{"DATABASE_DEMO_IMPORTER_URL", databaseURL("sentinelflow_demo_importer", demoImporterPassword)},
		{"DATABASE_DEMO_ACTIVATOR_URL", databaseURL("sentinelflow_demo_activator", demoActivatorPassword)},
		{"GATEWAY_EVENT_HMAC_KEY", gatewayKey},
		{"GATEWAY_EVENT_HMAC_KEY_ID", gatewayKeyID},
		{"GATEWAY_EXPECTED_SOURCE_BINDING_ID", gatewayBindingID},
		{"GATEWAY_SOURCE_CONFIG_SHA256", producerConfigDigest(gatewayProducerConfigV1)},
		{"AUTH_EVENT_HMAC_KEY", authKey},
		{"AUTH_EVENT_HMAC_KEY_ID", authKeyID},
		{"AUTH_EXPECTED_SOURCE_BINDING_ID", authBindingID},
		{"AUTH_SOURCE_CONFIG_SHA256", producerConfigDigest(authProducerConfigV1)},
		{"AUTH_ACCOUNT_HASH_KEY", accountKey},
		{"ADMIN_USERNAME", input.adminUsername},
		{"ADMIN_PASSWORD_ARGON2ID_HASH", passwordHash},
		{"SESSION_HMAC_KEY", sessionKey},
		{"NFT_BINARY_EXPECTED_SHA256", input.nftBinarySHA256},
		{"NFT_EXPECTED_VERSION", input.nftVersion},
		{"DEMO_HISTORY_FIXTURE_DATASET", demoDatasetContainerPath},
		{"DEMO_HISTORY_SIGNED_ENVELOPE_FILE", demoEnvelopeContainerPath},
		{"DEMO_HISTORY_PUBLIC_KEY_B64URL", historyAssertions.PublicKeyB64URL()},
		{"DEMO_HISTORY_RUN_SCOPE", historyAssertions.RunScope()},
		{"DEMO_HISTORY_IMPORT_ID", historyAssertions.ImportID()},
		{"DEMO_HISTORY_CLOCK_AT", historyAssertions.ClockAt().Format("2006-01-02T15:04:05.000Z")},
		{"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST", historyAssertions.ImpactSourceHealthDigest()},
		{"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE", demoAnalysisActivationContainerPath},
		{"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE", demoValidationActivationContainerPath},
		{"OPENAI_RATE_CARD_VERSION", ""},
		{"OPENAI_INPUT_USD_PER_1M_TOKENS", ""},
		{"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS", ""},
		{"OPENAI_OUTPUT_USD_PER_1M_TOKENS", ""},
	}
	var environment strings.Builder
	environment.WriteString("# Generated by cmd/democonfig. Ignored by Git; do not commit.\n")
	environment.WriteString("# Fill the four operator rate-card fields before starting live AI.\n")
	for _, value := range values {
		encoded, encodeErr := envValue(value[1])
		if encodeErr != nil {
			return generatedValues{}, errors.New("could not encode local environment")
		}
		environment.WriteString(value[0])
		environment.WriteByte('=')
		environment.WriteString(encoded)
		environment.WriteByte('\n')
	}
	result.environment = []byte(environment.String())
	return result, nil
}

func passwordPHC(password []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	defer clear(salt)
	sum := argon2.IDKey(password, salt, argonIterations, argonMemoryKiB, argonParallelism, 32)
	defer clear(sum)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemoryKiB, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

func randomBase64(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	defer clear(value)
	return base64.StdEncoding.EncodeToString(value), nil
}

func randomSecret(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("invalid secret size")
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func randomText(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	defer clear(value)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func eventKeyID(prefix, encoded string) (string, error) {
	if !keyIdentityPrefix.MatchString(prefix) {
		return "", errors.New("invalid key identity prefix")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != secretBytes {
		clear(raw)
		return "", errors.New("invalid event key")
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return prefix + "-" + hex.EncodeToString(sum[:keyIdentityDigestBytes]), nil
}

func randomUUIDv4() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	defer clear(value)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func producerConfigDigest(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func databaseURL(role, password string) string {
	return "postgresql://" + role + ":" + password + "@postgres:5432/sentinelflow?sslmode=disable"
}

func privatePEM(key ed25519.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

func publicPEM(key ed25519.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), nil
}

func envValue(value string) (string, error) {
	if strings.ContainsAny(value, "'\r\n\x00") {
		return "", errors.New("unsupported environment value")
	}
	return "'" + value + "'", nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(mode); err != nil {
		return err
	}
	written, err := file.Write(contents)
	if err != nil {
		return err
	}
	if written != len(contents) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err = parent.Sync(); err != nil {
		_ = parent.Close()
		return err
	}
	if err = parent.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func (value *generatedValues) clear() {
	if value == nil {
		return
	}
	clear(value.environment)
	clear(value.credentials)
	clear(value.analysisActivation)
	clear(value.validationActivation)
	clear(value.dispatchPrivate)
	clear(value.dispatchPublic)
	clear(value.resultPrivate)
	clear(value.resultPublic)
	clear(value.historyEnvelope)
	clear(value.historyAssertions)
}
