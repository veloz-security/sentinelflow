package detection

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

const (
	DefaultConfigurationVersion = "detectors-v1"
	DefaultPathCatalogVersion   = "path-catalog-v1"
	DefaultLoginRouteLabel      = "login"

	PathScanThreshold                  = 8
	RequestBurstThreshold              = 120
	LoginBruteForceThreshold           = 10
	CredentialStuffingEventThreshold   = 20
	CredentialStuffingAccountThreshold = 8
)

const (
	PathScanWindow           = 60 * time.Second
	RequestBurstWindow       = 10 * time.Second
	LoginBruteForceWindow    = 60 * time.Second
	CredentialStuffingWindow = 5 * time.Minute
)

var versionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// Config exposes the frozen v0.1 thresholds and the versioned deployment
// labels. New rejects threshold or window drift; changing those contracts first
// requires the corresponding documentation and decision workflow.
type Config struct {
	Version                            string
	PathCatalogVersion                 string
	LoginRouteLabel                    string
	SuspiciousPathIDs                  []SuspiciousPathID
	PathScanThreshold                  int
	PathScanWindow                     time.Duration
	RequestBurstThreshold              int
	RequestBurstWindow                 time.Duration
	LoginBruteForceThreshold           int
	LoginBruteForceWindow              time.Duration
	CredentialStuffingEventThreshold   int
	CredentialStuffingAccountThreshold int
	CredentialStuffingWindow           time.Duration
}

func DefaultConfig() Config {
	return Config{
		Version:                            DefaultConfigurationVersion,
		PathCatalogVersion:                 DefaultPathCatalogVersion,
		LoginRouteLabel:                    DefaultLoginRouteLabel,
		SuspiciousPathIDs:                  defaultSuspiciousPathIDs(),
		PathScanThreshold:                  PathScanThreshold,
		PathScanWindow:                     PathScanWindow,
		RequestBurstThreshold:              RequestBurstThreshold,
		RequestBurstWindow:                 RequestBurstWindow,
		LoginBruteForceThreshold:           LoginBruteForceThreshold,
		LoginBruteForceWindow:              LoginBruteForceWindow,
		CredentialStuffingEventThreshold:   CredentialStuffingEventThreshold,
		CredentialStuffingAccountThreshold: CredentialStuffingAccountThreshold,
		CredentialStuffingWindow:           CredentialStuffingWindow,
	}
}

func defaultSuspiciousPathIDs() []SuspiciousPathID {
	return []SuspiciousPathID{
		SuspiciousPathAdminConsole,
		SuspiciousPathEnvFile,
		SuspiciousPathGitConfig,
		SuspiciousPathWPAdmin,
		SuspiciousPathPHPMyAdmin,
		SuspiciousPathServerStatus,
		SuspiciousPathActuatorEnv,
		SuspiciousPathBackupArchive,
	}
}

type Detector struct {
	config       Config
	configDigest string
}

func New(config Config) (*Detector, error) {
	normalized, err := validateAndNormalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Detector{
		config:       normalized,
		configDigest: digestConfig(normalized),
	}, nil
}

func NewDefault() *Detector {
	detector, err := New(DefaultConfig())
	if err != nil {
		panic("detection: invalid built-in configuration: " + err.Error())
	}
	return detector
}

// Config returns a defensive copy; callers cannot mutate active rule state.
func (d *Detector) Config() Config {
	config := d.config
	config.SuspiciousPathIDs = append([]SuspiciousPathID(nil), d.config.SuspiciousPathIDs...)
	return config
}

func (d *Detector) ConfigurationDigest() string {
	return d.configDigest
}

func validateAndNormalizeConfig(config Config) (Config, error) {
	if !versionPattern.MatchString(config.Version) {
		return Config{}, fmt.Errorf("configuration version must be a lowercase version label")
	}
	if config.PathCatalogVersion != DefaultPathCatalogVersion {
		return Config{}, fmt.Errorf("path catalog version must be %q", DefaultPathCatalogVersion)
	}
	if !labelPattern.MatchString(config.LoginRouteLabel) {
		return Config{}, fmt.Errorf("login route label is invalid")
	}
	if config.PathScanThreshold != PathScanThreshold || config.PathScanWindow != PathScanWindow {
		return Config{}, fmt.Errorf("path scan contract must remain %d events in %s", PathScanThreshold, PathScanWindow)
	}
	if config.RequestBurstThreshold != RequestBurstThreshold || config.RequestBurstWindow != RequestBurstWindow {
		return Config{}, fmt.Errorf("request burst contract must remain %d events in %s", RequestBurstThreshold, RequestBurstWindow)
	}
	if config.LoginBruteForceThreshold != LoginBruteForceThreshold || config.LoginBruteForceWindow != LoginBruteForceWindow {
		return Config{}, fmt.Errorf("login brute-force contract must remain %d events in %s", LoginBruteForceThreshold, LoginBruteForceWindow)
	}
	if config.CredentialStuffingEventThreshold != CredentialStuffingEventThreshold ||
		config.CredentialStuffingAccountThreshold != CredentialStuffingAccountThreshold ||
		config.CredentialStuffingWindow != CredentialStuffingWindow {
		return Config{}, fmt.Errorf("credential stuffing contract must remain %d events across %d accounts in %s", CredentialStuffingEventThreshold, CredentialStuffingAccountThreshold, CredentialStuffingWindow)
	}

	expected := defaultSuspiciousPathIDs()
	actual := append([]SuspiciousPathID(nil), config.SuspiciousPathIDs...)
	sort.Slice(actual, func(i, j int) bool { return actual[i] < actual[j] })
	sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })
	if len(actual) != len(expected) {
		return Config{}, fmt.Errorf("suspicious path set must contain exactly %d identifiers", len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return Config{}, fmt.Errorf("suspicious path set must equal path-catalog-v1")
		}
	}
	config.SuspiciousPathIDs = actual
	return config, nil
}
