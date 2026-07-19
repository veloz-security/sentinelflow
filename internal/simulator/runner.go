package simulator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxConcurrency         = 32
	maxGatewayURLBytes     = 2048
	maxResponseBodyBytes   = 4096
	maxResponseHeaderBytes = 32768
	userAgent              = "sentinelflow-simulator/v1"
	defaultRequestLimit    = 10 * time.Second
	defaultNormalRunLimit  = 30 * time.Second
)

var (
	ErrInvalidRunner = errors.New("simulator runner configuration is invalid")
	ErrRunFailed     = errors.New("simulator run failed")
	errRedirect      = errors.New("simulator redirect blocked")
)

type RunnerConfig struct {
	BaseURL        string
	HostHeader     string
	Concurrency    int
	RequestTimeout time.Duration
}

// Runner owns a single hardened HTTP/1.1 client. Its transport never consults
// proxy environment variables, never negotiates HTTP/2, bounds connections,
// response headers, response bodies, and time, and refuses every redirect.
type Runner struct {
	baseURL        url.URL
	hostHeader     string
	client         *http.Client
	concurrency    int
	requestTimeout time.Duration
}

type StatusCount struct {
	Class string `json:"class"`
	Count int    `json:"count"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Result        string        `json:"result"`
	Scenario      Scenario      `json:"scenario"`
	Seed          int64         `json:"seed"`
	PlanDigest    string        `json:"plan_digest"`
	ExpectedShape ExpectedShape `json:"expected_shape"`
	Attempted     int           `json:"attempted"`
	Completed     int           `json:"completed"`
	Failed        int           `json:"failed"`
	StatusCounts  []StatusCount `json:"status_counts"`
}

func NewRunner(config RunnerConfig) (*Runner, error) {
	parsed, err := parseGatewayURL(config.BaseURL)
	hostHeader := config.HostHeader
	if hostHeader == "" && err == nil {
		hostHeader = parsed.Host
	}
	if err != nil || !validGatewayHostHeader(hostHeader) ||
		config.Concurrency < 1 || config.Concurrency > maxConcurrency {
		return nil, ErrInvalidRunner
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestLimit
	}
	if config.RequestTimeout < 100*time.Millisecond || config.RequestTimeout > 30*time.Second {
		return nil, ErrInvalidRunner
	}

	transport := newGatewayTransport(config.Concurrency, config.RequestTimeout)
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
	return &Runner{
		baseURL:        parsed,
		hostHeader:     hostHeader,
		client:         client,
		concurrency:    config.Concurrency,
		requestTimeout: config.RequestTimeout,
	}, nil
}

func validGatewayHostHeader(raw string) bool {
	if raw == "" || len(raw) > 255 || strings.TrimSpace(raw) != raw {
		return false
	}
	parsed, err := url.Parse("http://" + raw)
	return err == nil && parsed.Scheme == "http" && parsed.Host == raw && parsed.User == nil &&
		parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery &&
		parsed.Fragment == "" && validGatewayAuthority(parsed.Host, parsed.Hostname(), parsed.Port())
}

func parseGatewayURL(raw string) (url.URL, error) {
	if raw == "" || len(raw) > maxGatewayURLBytes || !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw {
		return url.URL{}, ErrInvalidRunner
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") || !validGatewayAuthority(parsed.Host, parsed.Hostname(), parsed.Port()) {
		return url.URL{}, ErrInvalidRunner
	}
	canonical := parsed.Scheme + "://" + parsed.Host
	if raw != canonical && raw != canonical+"/" {
		return url.URL{}, ErrInvalidRunner
	}
	parsed.Path = ""
	return *parsed, nil
}

func validGatewayAuthority(authority, hostname, port string) bool {
	if authority != strings.ToLower(authority) || hostname == "" || len(hostname) > 253 ||
		strings.ContainsAny(authority, "%\\\r\n\t ") || strings.Contains(hostname, ":") {
		return false
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		if !address.Is4() || address.String() != hostname {
			return false
		}
	} else {
		if hostname[0] == '.' || hostname[len(hostname)-1] == '.' {
			return false
		}
		for _, label := range strings.Split(hostname, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, character := range label {
				if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
					return false
				}
			}
		}
	}
	if strings.Contains(authority, ":") {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port || authority != hostname+":"+port {
			return false
		}
	}
	return true
}

func newGatewayTransport(concurrency int, timeout time.Duration) *http.Transport {
	dialTimeout := timeout
	if dialTimeout > 5*time.Second {
		dialTimeout = 5 * time.Second
	}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      false,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSNextProto:           make(map[string]func(string, *tls.Conn) http.RoundTripper),
		MaxIdleConns:           concurrency,
		MaxIdleConnsPerHost:    concurrency,
		MaxConnsPerHost:        concurrency,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DisableCompression:     true,
	}
}

func (r *Runner) Run(ctx context.Context, plan Plan) (Report, error) {
	canonical, planErr := BuildPlan(plan.scenario, plan.seed)
	if r == nil || r.client == nil || ctx == nil || planErr != nil || canonical.digest != plan.digest {
		return Report{}, ErrRunFailed
	}

	report := Report{
		SchemaVersion: "simulator-report-v1",
		Result:        "failed",
		Scenario:      canonical.scenario,
		Seed:          canonical.seed,
		PlanDigest:    canonical.digest,
		ExpectedShape: canonical.ExpectedShape(),
		Attempted:     len(canonical.requests),
		StatusCounts:  []StatusCount{},
	}
	runLimit := defaultNormalRunLimit
	if report.ExpectedShape.BoundaryWindowSeconds > 0 {
		runLimit = time.Duration(report.ExpectedShape.BoundaryWindowSeconds) * time.Second
	}
	runContext, cancel := context.WithTimeout(ctx, runLimit)
	defer cancel()

	type result struct {
		statusClass string
		err         error
	}
	jobs := make(chan requestSpec)
	results := make(chan result, len(canonical.requests))
	var workers sync.WaitGroup
	for range r.concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for request := range jobs {
				statusClass, err := r.runOne(runContext, request)
				results <- result{statusClass: statusClass, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, request := range canonical.requests {
			select {
			case jobs <- request:
			case <-runContext.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	counts := make(map[string]int)
	for outcome := range results {
		if outcome.err != nil {
			report.Failed++
			continue
		}
		report.Completed++
		counts[outcome.statusClass]++
	}
	for statusClass, count := range counts {
		report.StatusCounts = append(report.StatusCounts, StatusCount{Class: statusClass, Count: count})
	}
	sort.Slice(report.StatusCounts, func(i, j int) bool {
		return report.StatusCounts[i].Class < report.StatusCounts[j].Class
	})
	if missing := report.Attempted - report.Completed - report.Failed; missing > 0 {
		// Cancellation can stop the producer before a job is handed to a
		// worker. Those unstarted requests remain explicit failed work.
		report.Failed += missing
	}
	if report.Failed != 0 || report.Completed != report.Attempted {
		return report, ErrRunFailed
	}
	report.Result = "passed"
	return report, nil
}

func (r *Runner) runOne(parent context.Context, spec requestSpec) (string, error) {
	requestContext, cancel := context.WithTimeout(parent, r.requestTimeout)
	defer cancel()

	target := r.baseURL
	target.Path = spec.path
	target.RawPath = ""
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	target.RawFragment = ""
	var body io.Reader
	if spec.body != "" {
		body = strings.NewReader(spec.body)
	}
	request, err := http.NewRequestWithContext(requestContext, spec.method, target.String(), body)
	if err != nil {
		return "", ErrRunFailed
	}
	request.Header.Set("User-Agent", userAgent)
	request.Host = r.hostHeader
	if spec.contentType != "" {
		request.Header.Set("Content-Type", spec.contentType)
	}

	response, err := r.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return "", ErrRunFailed
	}
	if response == nil || response.Body == nil {
		return "", ErrRunFailed
	}
	if response.ContentLength > maxResponseBodyBytes {
		_ = response.Body.Close()
		return "", ErrRunFailed
	}
	read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBodyBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || read > maxResponseBodyBytes ||
		response.StatusCode < 100 || response.StatusCode > 599 || !spec.acceptsStatus(response.StatusCode) {
		return "", ErrRunFailed
	}
	return strconv.Itoa(response.StatusCode/100) + "xx", nil
}

func (r Report) String() string {
	return fmt.Sprintf("simulator-report{result=%s,scenario=%s,seed=%d,attempted=%d,completed=%d,failed=%d,digest=%s}",
		r.Result, r.Scenario, r.Seed, r.Attempted, r.Completed, r.Failed, r.PlanDigest)
}

func (r *Runner) String() string {
	if r == nil {
		return "simulator-runner{invalid}"
	}
	return fmt.Sprintf("simulator-runner{scheme=%s,host=[REDACTED],concurrency=%d}", r.baseURL.Scheme, r.concurrency)
}
