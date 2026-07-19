package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/demohistoryseal"
	"github.com/devwooops/sentinelflow/internal/keymaterial"
	"github.com/devwooops/sentinelflow/internal/validation"
)

func TestGenerateCreatesUsableLeastPrivilegeBundleAndRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	environmentPath := filepath.Join(root, ".env.demo")
	secretsPath := filepath.Join(root, "secrets", "demo")
	password := []byte("correct-horse-battery-staple")
	input := options{
		environmentFile:  environmentPath,
		secretsDirectory: secretsPath,
		historyDirectory: filepath.Join(root, "data", "demo-history"),
		repositoryRoot:   testRepositoryRoot(t),
		adminUsername:    "admin",
		adminPassword:    password,
		nftBinarySHA256:  strings.Repeat("a", 64),
		nftVersion:       "nftables v1.1.6",
		now:              time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC),
	}
	if err := generate(input); err != nil {
		t.Fatal(err)
	}
	assertMode(t, environmentPath, 0o600)
	assertMode(t, secretsPath, 0o700)
	assertMode(t, filepath.Join(secretsPath, "admin-credentials.json"), 0o600)
	assertRegularMode(t, filepath.Join(secretsPath, "demo-history-analysis-activation.capability"), 0o400)
	assertRegularMode(t, filepath.Join(secretsPath, "demo-history-validation-activation.capability"), 0o400)
	assertMode(t, filepath.Join(secretsPath, "dispatcher-capability-private.pem"), 0o600)
	assertMode(t, filepath.Join(secretsPath, "dispatcher-capability-public.pem"), 0o644)
	assertMode(t, filepath.Join(secretsPath, "executor-result-private.pem"), 0o600)
	assertMode(t, filepath.Join(secretsPath, "executor-result-public.pem"), 0o644)
	assertMode(t, input.historyDirectory, 0o755)
	assertMode(t, filepath.Join(input.historyDirectory, demohistoryseal.EnvelopeFileName), 0o444)
	assertMode(t, filepath.Join(input.historyDirectory, demohistoryseal.AssertionsFileName), 0o444)

	environmentBytes, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(environmentBytes, password) || bytes.Contains(environmentBytes, []byte("OPENAI_API_KEY")) {
		t.Fatal("environment file contains a plaintext administrator password or OpenAI key field")
	}
	if bytes.Contains(environmentBytes, []byte("DEMO_HISTORY_SIMULATOR_PRIVATE_KEY")) ||
		bytes.Contains(environmentBytes, []byte("DEMO_HISTORY_PRIVATE")) {
		t.Fatal("environment file contains demo-history private-key configuration")
	}
	environment := parseEnvironment(t, environmentBytes)
	if environment["COMPOSE_PROFILES"] != "stub-ai" {
		t.Fatal("generated demo configuration did not select exactly one deterministic analysis profile")
	}
	for _, required := range []string{
		"POSTGRES_PASSWORD", "DATABASE_API_PASSWORD", "DATABASE_WORKER_PASSWORD",
		"DATABASE_READ_PASSWORD", "DATABASE_DISPATCHER_PASSWORD", "DATABASE_RETENTION_PASSWORD",
		"DATABASE_LIFECYCLE_PASSWORD", "DATABASE_METRICS_PASSWORD",
		"DATABASE_DEMO_IMPORTER_PASSWORD", "DATABASE_DEMO_ACTIVATOR_PASSWORD",
		"DATABASE_API_URL", "DATABASE_WORKER_URL", "DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL", "DATABASE_RETENTION_URL", "DATABASE_LIFECYCLE_URL",
		"DATABASE_METRICS_URL", "DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL",
		"GATEWAY_EVENT_HMAC_KEY", "AUTH_EVENT_HMAC_KEY", "AUTH_ACCOUNT_HASH_KEY",
		"GATEWAY_EVENT_HMAC_KEY_ID", "AUTH_EVENT_HMAC_KEY_ID",
		"GATEWAY_EXPECTED_SOURCE_BINDING_ID", "AUTH_EXPECTED_SOURCE_BINDING_ID",
		"GATEWAY_SOURCE_CONFIG_SHA256", "AUTH_SOURCE_CONFIG_SHA256",
		"ADMIN_PASSWORD_ARGON2ID_HASH", "SESSION_HMAC_KEY",
		"NFT_BINARY_EXPECTED_SHA256", "NFT_EXPECTED_VERSION",
		"DEMO_HISTORY_FIXTURE_DATASET", "DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL", "DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT", "DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		if environment[required] == "" {
			t.Fatalf("required generated value %s is empty", required)
		}
	}
	if environment["DEMO_HISTORY_FIXTURE_DATASET"] != demoDatasetContainerPath ||
		environment["DEMO_HISTORY_SIGNED_ENVELOPE_FILE"] != demoEnvelopeContainerPath ||
		environment["DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE"] != demoAnalysisActivationContainerPath ||
		environment["DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE"] != demoValidationActivationContainerPath ||
		environment["DEMO_HISTORY_PUBLIC_KEY_B64URL"] == validation.PinnedDemoHistoryFixturePublicKey ||
		!strings.HasSuffix(environment["DEMO_HISTORY_CLOCK_AT"], ".000Z") {
		t.Fatal("generated public history environment assertions are invalid")
	}
	assertSourceIdentity(t, environment)
	for key, role := range map[string]string{
		"DATABASE_API_URL":            "sentinelflow_api",
		"DATABASE_WORKER_URL":         "sentinelflow_worker",
		"DATABASE_READ_URL":           "sentinelflow_read",
		"DATABASE_DISPATCHER_URL":     "sentinelflow_dispatcher",
		"DATABASE_RETENTION_URL":      "sentinelflow_retention",
		"DATABASE_LIFECYCLE_URL":      "sentinelflow_lifecycle",
		"DATABASE_METRICS_URL":        "sentinelflow_metrics",
		"DATABASE_DEMO_IMPORTER_URL":  "sentinelflow_demo_importer",
		"DATABASE_DEMO_ACTIVATOR_URL": "sentinelflow_demo_activator",
	} {
		parsed, parseErr := url.Parse(environment[key])
		if parseErr != nil || parsed.Scheme != "postgresql" || parsed.User == nil || parsed.User.Username() != role ||
			parsed.Host != "postgres:5432" || parsed.Path != "/sentinelflow" || parsed.RawQuery != "sslmode=disable" {
			t.Fatalf("invalid generated database URL for %s", key)
		}
		password, ok := parsed.User.Password()
		passwordName := strings.TrimSuffix(key, "_URL") + "_PASSWORD"
		if !ok || password != environment[passwordName] {
			t.Fatalf("generated database URL does not bind %s", passwordName)
		}
	}
	seenDatabaseCredentials := make(map[string]string)
	for _, name := range []string{
		"POSTGRES_PASSWORD", "DATABASE_API_PASSWORD", "DATABASE_WORKER_PASSWORD",
		"DATABASE_READ_PASSWORD", "DATABASE_DISPATCHER_PASSWORD", "DATABASE_RETENTION_PASSWORD",
		"DATABASE_LIFECYCLE_PASSWORD", "DATABASE_METRICS_PASSWORD",
		"DATABASE_DEMO_IMPORTER_PASSWORD", "DATABASE_DEMO_ACTIVATOR_PASSWORD",
	} {
		if prior, exists := seenDatabaseCredentials[environment[name]]; exists {
			t.Fatalf("database credential was reused by %s and %s", prior, name)
		}
		seenDatabaseCredentials[environment[name]] = name
	}
	analysisActivation, err := os.ReadFile(filepath.Join(secretsPath, "demo-history-analysis-activation.capability"))
	if err != nil {
		t.Fatal(err)
	}
	validationActivation, err := os.ReadFile(filepath.Join(secretsPath, "demo-history-validation-activation.capability"))
	if err != nil {
		t.Fatal(err)
	}
	if len(analysisActivation) != secretBytes || len(validationActivation) != secretBytes ||
		bytes.Equal(analysisActivation, make([]byte, secretBytes)) ||
		bytes.Equal(validationActivation, make([]byte, secretBytes)) ||
		bytes.Equal(analysisActivation, validationActivation) {
		t.Fatal("generated demo-history activation capabilities are not distinct raw 32-byte secrets")
	}
	if bytes.Contains(environmentBytes, analysisActivation) || bytes.Contains(environmentBytes, validationActivation) {
		t.Fatal("generated environment contains raw demo-history activation capability bytes")
	}
	defer clear(analysisActivation)
	defer clear(validationActivation)
	verifier, err := adminauth.NewCredentialVerifier("admin", "administrator", environment["ADMIN_PASSWORD_ARGON2ID_HASH"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.Verify("admin", password); err != nil {
		t.Fatal("generated administrator verifier rejected its credential")
	}

	credentialsBytes, err := os.ReadFile(filepath.Join(secretsPath, "admin-credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	var credentials credentialsFile
	if err = json.Unmarshal(credentialsBytes, &credentials); err != nil || credentials.Username != "admin" || credentials.Password != string(password) || credentials.GeneratedAt != "2026-07-18T09:00:00Z" {
		t.Fatal("generated credentials file did not round-trip")
	}
	if bytes.Contains(credentialsBytes, analysisActivation) || bytes.Contains(credentialsBytes, validationActivation) {
		t.Fatal("generated credentials contain raw demo-history activation capability bytes")
	}
	dispatchPrivate, err := keymaterial.LoadPrivateFile(filepath.Join(secretsPath, "dispatcher-capability-private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	dispatchPublic, err := keymaterial.LoadPublicFile(filepath.Join(secretsPath, "dispatcher-capability-public.pem"))
	if err != nil || !bytes.Equal(dispatchPrivate[32:], dispatchPublic) {
		t.Fatal("dispatcher public/private key pair mismatch")
	}
	resultPrivate, err := keymaterial.LoadPrivateFile(filepath.Join(secretsPath, "executor-result-private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	resultPublic, err := keymaterial.LoadPublicFile(filepath.Join(secretsPath, "executor-result-public.pem"))
	if err != nil || !bytes.Equal(resultPrivate[32:], resultPublic) || bytes.Equal(dispatchPublic, resultPublic) {
		t.Fatal("executor result key pair mismatch or key roles were reused")
	}
	clear(dispatchPrivate)
	clear(resultPrivate)
	historyEnvelope, err := os.ReadFile(filepath.Join(input.historyDirectory, demohistoryseal.EnvelopeFileName))
	if err != nil {
		t.Fatal(err)
	}
	historyAssertions, err := os.ReadFile(filepath.Join(input.historyDirectory, demohistoryseal.AssertionsFileName))
	if err != nil {
		t.Fatal(err)
	}
	dataset, err := os.ReadFile(filepath.Join(input.repositoryRoot, validation.DemoHistoryDatasetLocator))
	if err != nil {
		t.Fatal(err)
	}
	if _, assertions, verifyErr := demohistoryseal.VerifyBundle(context.Background(), dataset, historyEnvelope, historyAssertions); verifyErr != nil || assertions.PublicKeyB64URL() == validation.PinnedDemoHistoryFixturePublicKey {
		t.Fatalf("generated history authority did not verify: %v", verifyErr)
	}
	if bytes.Contains(historyEnvelope, analysisActivation) || bytes.Contains(historyEnvelope, validationActivation) ||
		bytes.Contains(historyAssertions, analysisActivation) || bytes.Contains(historyAssertions, validationActivation) {
		t.Fatal("public history artifacts contain raw demo-history activation capability bytes")
	}
	parsedAssertions, err := demohistoryseal.ParseAssertions(historyAssertions)
	if err != nil || environment["DEMO_HISTORY_PUBLIC_KEY_B64URL"] != parsedAssertions.PublicKeyB64URL() ||
		environment["DEMO_HISTORY_RUN_SCOPE"] != parsedAssertions.RunScope() ||
		environment["DEMO_HISTORY_IMPORT_ID"] != parsedAssertions.ImportID() ||
		environment["DEMO_HISTORY_CLOCK_AT"] != parsedAssertions.ClockAt().Format("2006-01-02T15:04:05.000Z") ||
		environment["DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"] != parsedAssertions.ImpactSourceHealthDigest() {
		t.Fatal("environment handoff drifted from public assertion bundle")
	}
	for _, forbidden := range [][]byte{
		[]byte("PRIVATE KEY"), []byte("private_key"), []byte("OPENAI_API_KEY"),
		[]byte("dispatcher-capability"), []byte("executor-result"), []byte("ADMIN_PASSWORD"),
	} {
		if bytes.Contains(historyEnvelope, forbidden) || bytes.Contains(historyAssertions, forbidden) {
			t.Fatal("public history bundle contains private or unrelated authority material")
		}
	}

	before := append([]byte(nil), environmentBytes...)
	if err = generate(input); err == nil {
		t.Fatal("second generation overwrote an existing bundle")
	}
	after, err := os.ReadFile(environmentPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("overwrite rejection changed the existing environment bundle")
	}
	analysisAfter, err := os.ReadFile(filepath.Join(secretsPath, "demo-history-analysis-activation.capability"))
	if err != nil || !bytes.Equal(analysisActivation, analysisAfter) {
		t.Fatal("overwrite rejection changed the analysis activation capability")
	}
	validationAfter, err := os.ReadFile(filepath.Join(secretsPath, "demo-history-validation-activation.capability"))
	if err != nil || !bytes.Equal(validationActivation, validationAfter) {
		t.Fatal("overwrite rejection changed the validation activation capability")
	}
	clear(analysisAfter)
	clear(validationAfter)
}

func TestRunStatusDoesNotExposeGeneratedActivationCapabilities(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	t.Chdir(repositoryRoot)
	root := t.TempDir()
	environmentPath := filepath.Join(root, ".env.demo")
	secretsPath := filepath.Join(root, "secrets", "demo")
	historyPath := filepath.Join(root, "data", "demo-history")
	lookup := func(name string) string {
		return map[string]string{
			adminPasswordVariable: "correct-horse-battery-staple",
			nftDigestVariable:     strings.Repeat("a", 64),
			nftVersionVariable:    "nftables v1.1.6",
		}[name]
	}
	var output bytes.Buffer
	if err := run([]string{
		"--output", environmentPath,
		"--secrets-dir", secretsPath,
		"--history-dir", historyPath,
	}, lookup, &output); err != nil {
		t.Fatal(err)
	}
	analysisActivation, err := os.ReadFile(filepath.Join(secretsPath, "demo-history-analysis-activation.capability"))
	if err != nil {
		t.Fatal(err)
	}
	validationActivation, err := os.ReadFile(filepath.Join(secretsPath, "demo-history-validation-activation.capability"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(analysisActivation)
	defer clear(validationActivation)
	if bytes.Contains(output.Bytes(), analysisActivation) || bytes.Contains(output.Bytes(), validationActivation) {
		t.Fatal("status output contains raw demo-history activation capability bytes")
	}
}

func TestGenerateOverridesRestrictiveUmaskWithExactPublicAndPrivateModes(t *testing.T) {
	previousUmask := syscall.Umask(0o077)
	defer syscall.Umask(previousUmask)

	root := t.TempDir()
	input := options{
		environmentFile:  filepath.Join(root, ".env.demo"),
		secretsDirectory: filepath.Join(root, "secrets", "demo"),
		historyDirectory: filepath.Join(root, "data", "demo-history"),
		repositoryRoot:   testRepositoryRoot(t),
		adminUsername:    "admin",
		adminPassword:    []byte("correct-horse-battery-staple"),
		nftBinarySHA256:  strings.Repeat("a", 64),
		nftVersion:       "nftables v1.1.6",
		now:              time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC),
	}
	if err := generate(input); err != nil {
		t.Fatal(err)
	}
	assertMode(t, input.environmentFile, 0o600)
	assertMode(t, input.secretsDirectory, 0o700)
	assertRegularMode(t, filepath.Join(input.secretsDirectory, "admin-credentials.json"), 0o600)
	assertRegularMode(t, filepath.Join(input.secretsDirectory, "demo-history-analysis-activation.capability"), 0o400)
	assertRegularMode(t, filepath.Join(input.secretsDirectory, "demo-history-validation-activation.capability"), 0o400)
	assertMode(t, input.historyDirectory, 0o755)
	for _, name := range []string{demohistoryseal.EnvelopeFileName, demohistoryseal.AssertionsFileName} {
		path := filepath.Join(input.historyDirectory, name)
		assertRegularMode(t, path, 0o444)
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm()&0o044 != 0o044 {
			t.Fatalf("%s is not non-owner-readable public history", name)
		}
	}
}

func TestSourceIdentityDerivationAndCanonicalProducerDigests(t *testing.T) {
	gatewayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, secretBytes))
	authKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, secretBytes))
	gatewayID, err := eventKeyID("gateway-key", gatewayKey)
	if err != nil {
		t.Fatal(err)
	}
	authID, err := eventKeyID("auth-key", authKey)
	if err != nil {
		t.Fatal(err)
	}
	if gatewayID != "gateway-key-72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30b" ||
		authID != "auth-key-75877bb41d393b5fb8455ce60ecd8dda001d06316496b14d" || gatewayID == authID {
		t.Fatalf("unexpected event key identities: %q %q", gatewayID, authID)
	}
	if producerConfigDigest(gatewayProducerConfigV1) != "9c4afd2b497c709b8220993cbbe782f2b4e55a9444be670035d50713c75fda67" ||
		producerConfigDigest(authProducerConfigV1) != "f91df0241d00aeed86c4c6094f1fb9e5923cb9627a6648520532de836034eb05" {
		t.Fatal("producer configuration digest golden value changed")
	}
	if _, err = eventKeyID("bad_prefix", gatewayKey); err == nil {
		t.Fatal("unsafe key identity prefix accepted")
	}
	first, err := randomUUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomUUIDv4()
	if err != nil || first == second || !canonicalUUIDv4(first) || !canonicalUUIDv4(second) {
		t.Fatal("UUIDv4 source binding identities are invalid")
	}
}

func TestGenerateRejectsUnsafeInputs(t *testing.T) {
	base := options{
		environmentFile:  filepath.Join(t.TempDir(), ".env.demo"),
		secretsDirectory: filepath.Join(t.TempDir(), "secrets"),
		historyDirectory: filepath.Join(t.TempDir(), "history"),
		repositoryRoot:   testRepositoryRoot(t),
		adminUsername:    "admin",
		adminPassword:    []byte("long-enough-password"),
		nftBinarySHA256:  strings.Repeat("a", 64),
		nftVersion:       "nftables v1.1.6",
		now:              time.Now().UTC(),
	}
	tests := []func(*options){
		func(value *options) { value.environmentFile = "bad/../.env" },
		func(value *options) { value.secretsDirectory = "bad/../secrets" },
		func(value *options) { value.historyDirectory = "bad/../history" },
		func(value *options) { value.repositoryRoot = "relative" },
		func(value *options) { value.adminUsername = "bad user" },
		func(value *options) { value.adminPassword = []byte("short") },
		func(value *options) { value.adminPassword = []byte("bad\npassword-that-is-long") },
		func(value *options) { value.nftBinarySHA256 = "bad" },
		func(value *options) { value.nftVersion = "1.1.6" },
		func(value *options) { value.now = time.Time{} },
	}
	for index, mutate := range tests {
		candidate := base
		candidate.adminPassword = append([]byte(nil), base.adminPassword...)
		mutate(&candidate)
		if err := generate(candidate); err == nil {
			t.Fatalf("unsafe input %d was accepted", index)
		}
	}
}

func testRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func assertRegularMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != want {
		t.Fatalf("%s does not satisfy its regular-file mode contract", filepath.Base(path))
	}
}

func assertSourceIdentity(t *testing.T, environment map[string]string) {
	t.Helper()
	for _, pair := range [][2]string{
		{"gateway-key", "GATEWAY_EVENT_HMAC_KEY"},
		{"auth-key", "AUTH_EVENT_HMAC_KEY"},
	} {
		want, err := eventKeyID(pair[0], environment[pair[1]])
		if err != nil {
			t.Fatal(err)
		}
		keyName := strings.TrimSuffix(pair[1], "KEY") + "KEY_ID"
		if environment[keyName] != want {
			t.Fatalf("%s does not bind its generated HMAC key", keyName)
		}
	}
	if environment["GATEWAY_EVENT_HMAC_KEY_ID"] == environment["AUTH_EVENT_HMAC_KEY_ID"] {
		t.Fatal("event key identities were reused")
	}
	for _, name := range []string{"GATEWAY_EXPECTED_SOURCE_BINDING_ID", "AUTH_EXPECTED_SOURCE_BINDING_ID"} {
		if !canonicalUUIDv4(environment[name]) {
			t.Fatalf("%s is not a canonical UUIDv4", name)
		}
	}
	if environment["GATEWAY_EXPECTED_SOURCE_BINDING_ID"] == environment["AUTH_EXPECTED_SOURCE_BINDING_ID"] {
		t.Fatal("source binding identities were reused")
	}
	if environment["GATEWAY_SOURCE_CONFIG_SHA256"] != producerConfigDigest(gatewayProducerConfigV1) ||
		environment["AUTH_SOURCE_CONFIG_SHA256"] != producerConfigDigest(authProducerConfigV1) {
		t.Fatal("source configuration digests do not match the explicit canonical producer configurations")
	}
}

func canonicalUUIDv4(value string) bool {
	return canonicalUUIDv4Pattern.MatchString(value)
}

func parseEnvironment(t *testing.T, contents []byte) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || len(parts[1]) < 2 || parts[1][0] != '\'' || parts[1][len(parts[1])-1] != '\'' {
			t.Fatalf("invalid environment line %q", line)
		}
		result[parts[0]] = parts[1][1 : len(parts[1])-1]
	}
	return result
}
