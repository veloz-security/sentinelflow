// Package simulator builds and runs deterministic, synthetic Gateway traffic.
// It never records request bodies, response bodies, or exact request paths in
// its reports.
package simulator

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Scenario string

const (
	ScenarioNormal             Scenario = "normal"
	ScenarioCredentialStuffing Scenario = "credential-stuffing"
	ScenarioBruteForce         Scenario = "brute-force"
	ScenarioPathScan           Scenario = "path-scan"
	ScenarioRequestBurst       Scenario = "request-burst"
)

const DefaultSeed int64 = 20260718

const (
	maxPlanSize  = 1000
	maxBodyBytes = 4096
)

var ErrInvalidPlan = errors.New("simulator plan is invalid")

type requestSpec struct {
	method              string
	path                string
	contentType         string
	body                string
	acceptedStatusCodes [2]int
	suspiciousPathID    string
}

// ExpectedShape is the privacy-safe, machine-checkable traffic boundary a
// plan is built to exercise. It describes generated input, not a claim that a
// detector, database, or incident pipeline accepted that input.
type ExpectedShape struct {
	ExpectedClassification    string   `json:"expected_classification"`
	GatewayRequestCount       int      `json:"gateway_request_count"`
	BrowseRequestCount        int      `json:"browse_request_count"`
	LoginFailureCount         int      `json:"login_failure_count"`
	DistinctAccountCount      int      `json:"distinct_account_count"`
	SuspiciousPathIDs         []string `json:"suspicious_path_ids"`
	BoundaryWindowSeconds     int      `json:"boundary_window_seconds"`
	IntermittentErrorRequests int      `json:"intermittent_error_requests"`
}

// Plan is an immutable deterministic sequence. Its request payloads are kept
// private so callers cannot accidentally include them in logs or reports.
type Plan struct {
	scenario Scenario
	seed     int64
	requests []requestSpec
	digest   string
}

func (p Plan) Scenario() Scenario { return p.scenario }
func (p Plan) Seed() int64        { return p.seed }
func (p Plan) RequestCount() int  { return len(p.requests) }
func (p Plan) Digest() string     { return p.digest }

func (p Plan) ExpectedShape() ExpectedShape {
	return expectedShape(p.scenario)
}

func (p Plan) String() string {
	return fmt.Sprintf("simulator-plan{scenario=%s,seed=%d,requests=%d,digest=%s}", p.scenario, p.seed, len(p.requests), p.digest)
}

func ParseScenario(value string) (Scenario, error) {
	scenario := Scenario(value)
	switch scenario {
	case ScenarioNormal, ScenarioCredentialStuffing, ScenarioBruteForce, ScenarioPathScan, ScenarioRequestBurst:
		return scenario, nil
	default:
		return "", ErrInvalidPlan
	}
}

func BuildPlan(scenario Scenario, seed int64) (Plan, error) {
	if _, err := ParseScenario(string(scenario)); err != nil || seed < 0 {
		return Plan{}, ErrInvalidPlan
	}
	requests := buildRequests(scenario, seed)
	if len(requests) == 0 || len(requests) > maxPlanSize {
		return Plan{}, ErrInvalidPlan
	}
	for _, request := range requests {
		if !validRequestSpec(request) {
			return Plan{}, ErrInvalidPlan
		}
	}
	requests = append([]requestSpec(nil), requests...)
	return Plan{
		scenario: scenario,
		seed:     seed,
		requests: requests,
		digest:   planDigest(scenario, seed, requests),
	}, nil
}

func buildRequests(scenario Scenario, seed int64) []requestSpec {
	suffix := strconv.FormatInt(seed%1_000_000, 10)
	safe := func(path string) requestSpec {
		return requestSpec{method: http.MethodGet, path: path, acceptedStatusCodes: [2]int{http.StatusOK}}
	}
	suspicious := func(path, identifier string) requestSpec {
		return requestSpec{
			method:              http.MethodGet,
			path:                path,
			acceptedStatusCodes: [2]int{http.StatusNotFound},
			suspiciousPathID:    identifier,
		}
	}
	login := func(account string) requestSpec {
		values := url.Values{
			"account":  []string{account},
			"password": []string{"synthetic-demo-input"},
		}
		return requestSpec{
			method:              http.MethodPost,
			path:                "/login",
			contentType:         "application/x-www-form-urlencoded",
			body:                values.Encode(),
			acceptedStatusCodes: [2]int{http.StatusUnauthorized},
		}
	}

	switch scenario {
	case ScenarioNormal:
		return []requestSpec{
			safe("/"), safe("/health"), safe("/products"), safe("/products/featured"),
			login("demo-normal-" + suffix), safe("/account"), {
				method:              http.MethodGet,
				path:                "/demo/intermittent-error",
				acceptedStatusCodes: [2]int{http.StatusOK, http.StatusServiceUnavailable},
			}, {
				method:              http.MethodGet,
				path:                "/demo/intermittent-error",
				acceptedStatusCodes: [2]int{http.StatusOK, http.StatusServiceUnavailable},
			},
		}
	case ScenarioCredentialStuffing:
		requests := make([]requestSpec, 0, 20)
		for index := range 20 {
			requests = append(requests, login(fmt.Sprintf("demo-stuff-%s-%02d", suffix, index%8)))
		}
		return requests
	case ScenarioBruteForce:
		requests := make([]requestSpec, 0, 10)
		for range 10 {
			requests = append(requests, login("demo-brute-"+suffix))
		}
		return requests
	case ScenarioPathScan:
		return []requestSpec{
			suspicious("/admin", "admin_console"), suspicious("/.env", "env_file"),
			suspicious("/.git/config", "git_config"), suspicious("/wp-admin", "wp_admin"),
			suspicious("/phpmyadmin", "phpmyadmin"), suspicious("/server-status", "server_status"),
			suspicious("/actuator/env", "actuator_env"), suspicious("/archive.zip", "backup_archive"),
		}
	case ScenarioRequestBurst:
		requests := make([]requestSpec, 0, 120)
		for range 120 {
			requests = append(requests, safe("/"))
		}
		return requests
	default:
		return nil
	}
}

func validRequestSpec(request requestSpec) bool {
	if request.method != http.MethodGet && request.method != http.MethodPost {
		return false
	}
	if len(request.path) == 0 || len(request.path) > 256 || request.path[0] != '/' ||
		strings.ContainsAny(request.path, "?#\r\n\\") || len(request.body) > maxBodyBytes {
		return false
	}
	if request.acceptedStatusCodes[0] < 100 || request.acceptedStatusCodes[0] > 599 ||
		(request.acceptedStatusCodes[1] != 0 &&
			(request.acceptedStatusCodes[1] < 100 || request.acceptedStatusCodes[1] > 599 ||
				request.acceptedStatusCodes[1] == request.acceptedStatusCodes[0])) {
		return false
	}
	if request.method == http.MethodGet {
		return request.body == "" && request.contentType == "" && validSuspiciousPathID(request.suspiciousPathID)
	}
	return request.path == "/login" && request.body != "" &&
		request.contentType == "application/x-www-form-urlencoded" && request.suspiciousPathID == ""
}

func validSuspiciousPathID(value string) bool {
	switch value {
	case "", "admin_console", "env_file", "git_config", "wp_admin", "phpmyadmin", "server_status", "actuator_env", "backup_archive":
		return true
	default:
		return false
	}
}

func (r requestSpec) acceptsStatus(status int) bool {
	return status == r.acceptedStatusCodes[0] || status == r.acceptedStatusCodes[1]
}

func expectedShape(scenario Scenario) ExpectedShape {
	shape := ExpectedShape{SuspiciousPathIDs: []string{}}
	switch scenario {
	case ScenarioNormal:
		shape.ExpectedClassification = "none"
		shape.GatewayRequestCount = 8
		shape.BrowseRequestCount = 5
		shape.LoginFailureCount = 1
		shape.DistinctAccountCount = 1
		shape.IntermittentErrorRequests = 2
	case ScenarioCredentialStuffing:
		shape.ExpectedClassification = "credential_stuffing"
		shape.GatewayRequestCount = 20
		shape.LoginFailureCount = 20
		shape.DistinctAccountCount = 8
		shape.BoundaryWindowSeconds = 300
	case ScenarioBruteForce:
		shape.ExpectedClassification = "brute_force"
		shape.GatewayRequestCount = 10
		shape.LoginFailureCount = 10
		shape.DistinctAccountCount = 1
		shape.BoundaryWindowSeconds = 60
	case ScenarioPathScan:
		shape.ExpectedClassification = "path_scan"
		shape.GatewayRequestCount = 8
		shape.SuspiciousPathIDs = []string{
			"admin_console", "env_file", "git_config", "wp_admin", "phpmyadmin", "server_status", "actuator_env", "backup_archive",
		}
		shape.BoundaryWindowSeconds = 60
	case ScenarioRequestBurst:
		shape.ExpectedClassification = "request_burst"
		shape.GatewayRequestCount = 120
		shape.BrowseRequestCount = 120
		shape.BoundaryWindowSeconds = 10
	}
	return shape
}

func planDigest(scenario Scenario, seed int64, requests []requestSpec) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "sentinelflow:simulator-plan:v2\x00")
	writeDigestField(hash, string(scenario))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(seed))
	_, _ = hash.Write(number[:])
	for _, request := range requests {
		writeDigestField(hash, request.method)
		writeDigestField(hash, request.path)
		writeDigestField(hash, request.contentType)
		bodySum := sha256.Sum256([]byte(request.body))
		_, _ = hash.Write(bodySum[:])
		var status [4]byte
		binary.BigEndian.PutUint32(status[:], uint32(request.acceptedStatusCodes[0]))
		_, _ = hash.Write(status[:])
		binary.BigEndian.PutUint32(status[:], uint32(request.acceptedStatusCodes[1]))
		_, _ = hash.Write(status[:])
		writeDigestField(hash, request.suspiciousPathID)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func writeDigestField(writer io.Writer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}
