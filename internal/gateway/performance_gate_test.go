package gateway

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/observability"
)

const (
	gateTargetRPS       = 500
	gateLatencyLimit    = 5 * time.Millisecond
	gateReleaseDuration = 5 * time.Minute
	gateWorkerCount     = 64
	gateHeapDeltaLimit  = 64 << 20
)

type gateLoadTarget struct {
	name   string
	url    string
	host   string
	client *http.Client
}

type gateLoadSample struct {
	latency time.Duration
	error   string
}

type gateLoadResult struct {
	name          string
	scheduled     int
	missed        int
	elapsed       time.Duration
	latencies     []time.Duration
	requestErrors int
	badStatuses   int
	badBodies     int
}

func (r gateLoadResult) p95() time.Duration { return gatePercentile(r.latencies, 0.95) }

func (r gateLoadResult) p99() time.Duration { return gatePercentile(r.latencies, 0.99) }

func (r gateLoadResult) rate() float64 {
	if r.elapsed <= 0 {
		return 0
	}
	return float64(r.scheduled-r.missed) / r.elapsed.Seconds()
}

func gatePercentile(values []time.Duration, percentile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := int(math.Ceil(float64(len(sorted))*percentile)) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func runGateLoad(start time.Time, duration time.Duration, target gateLoadTarget) gateLoadResult {
	requestCount := int((duration * gateTargetRPS) / time.Second)
	tasks := make(chan struct{}, gateWorkerCount*4)
	samples := make(chan gateLoadSample, gateWorkerCount*4)
	var workers sync.WaitGroup
	for range gateWorkerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range tasks {
				request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target.url+"/safe", nil)
				if err != nil {
					samples <- gateLoadSample{error: "request"}
					continue
				}
				if target.host != "" {
					request.Host = target.host
				}
				started := time.Now()
				response, err := target.client.Do(request)
				latency := time.Since(started)
				if err != nil {
					samples <- gateLoadSample{latency: latency, error: "transport"}
					continue
				}
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 64))
				closeErr := response.Body.Close()
				sample := gateLoadSample{latency: latency}
				switch {
				case readErr != nil || closeErr != nil:
					sample.error = "body"
				case response.StatusCode != http.StatusOK:
					sample.error = "status"
				case string(body) != "ok\n" || response.Header.Get("X-SentinelFlow-Synthetic-Origin") != "v1":
					sample.error = "parity"
				}
				samples <- sample
			}
		}()
	}

	result := gateLoadResult{name: target.name, scheduled: requestCount, latencies: make([]time.Duration, 0, requestCount)}
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for sample := range samples {
			result.latencies = append(result.latencies, sample.latency)
			switch sample.error {
			case "":
			case "status":
				result.badStatuses++
			case "parity":
				result.badBodies++
			default:
				result.requestErrors++
			}
		}
	}()

	if delay := time.Until(start); delay > 0 {
		time.Sleep(delay)
	}
	interval := time.Second / gateTargetRPS
	for index := range requestCount {
		targetTime := start.Add(time.Duration(index) * interval)
		if delay := time.Until(targetTime); delay > 0 {
			time.Sleep(delay)
		}
		select {
		case tasks <- struct{}{}:
		default:
			result.missed++
		}
	}
	close(tasks)
	workers.Wait()
	close(samples)
	<-collectorDone
	result.elapsed = time.Since(start)
	return result
}

type gateResourceSample struct {
	peakHeap       atomic.Uint64
	peakGoroutines atomic.Int64
	stop           chan struct{}
	done           chan struct{}
}

func startGateResourceSample() *gateResourceSample {
	sample := &gateResourceSample{stop: make(chan struct{}), done: make(chan struct{})}
	update := func() {
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		for {
			current := sample.peakHeap.Load()
			if memory.HeapInuse <= current || sample.peakHeap.CompareAndSwap(current, memory.HeapInuse) {
				break
			}
		}
		goroutines := int64(runtime.NumGoroutine())
		for {
			current := sample.peakGoroutines.Load()
			if goroutines <= current || sample.peakGoroutines.CompareAndSwap(current, goroutines) {
				break
			}
		}
	}
	update()
	go func() {
		defer close(sample.done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				update()
			case <-sample.stop:
				update()
				return
			}
		}
	}()
	return sample
}

func (s *gateResourceSample) close() {
	close(s.stop)
	<-s.done
}

func gateDurationEnv(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		t.Fatalf("%s must be a positive Go duration", name)
	}
	return duration
}

func gateClient(maxConnections int) (*http.Client, *http.Transport) {
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		MaxIdleConns:        maxConnections,
		MaxIdleConnsPerHost: maxConnections,
		MaxConnsPerHost:     maxConnections,
		IdleConnTimeout:     10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, transport
}

func assertGateLoad(t *testing.T, result gateLoadResult, minimumRate float64) {
	t.Helper()
	t.Logf("%s: scheduled=%d missed=%d rate=%.2f rps p95=%s p99=%s errors=%d status=%d parity=%d",
		result.name, result.scheduled, result.missed, result.rate(), result.p95(), result.p99(),
		result.requestErrors, result.badStatuses, result.badBodies)
	if result.missed != 0 || result.requestErrors != 0 || result.badStatuses != 0 || result.badBodies != 0 {
		t.Errorf("%s did not preserve request/response parity", result.name)
	}
	if len(result.latencies) != result.scheduled-result.missed {
		t.Errorf("%s samples=%d completed=%d", result.name, len(result.latencies), result.scheduled-result.missed)
	}
	if result.rate() < minimumRate {
		t.Errorf("%s rate %.2f rps is below %.2f rps", result.name, result.rate(), minimumRate)
	}
}

// TestGatewayPerformanceGate is opt-in because the release run lasts at least
// five minutes. The fixed workload compares concurrent 500 RPS direct-origin
// and Gateway paths against the same process-local origin after warm-up. The
// RFC1918 authority remains fixed and is mapped to loopback only inside the
// test transport, so the gate changes no host route, network namespace, or
// firewall state.
func TestGatewayPerformanceGate(t *testing.T) {
	if os.Getenv("SENTINELFLOW_GATEWAY_PERF") != "1" {
		t.Skip("set SENTINELFLOW_GATEWAY_PERF=1 to run the five-minute Gateway gate")
	}
	duration := gateDurationEnv(t, "SENTINELFLOW_GATEWAY_PERF_DURATION", gateReleaseDuration)
	warmup := gateDurationEnv(t, "SENTINELFLOW_GATEWAY_PERF_WARMUP", 10*time.Second)
	outageDuration := gateDurationEnv(t, "SENTINELFLOW_GATEWAY_PERF_OUTAGE_DURATION", 10*time.Second)
	shortRun := duration < gateReleaseDuration
	if shortRun && os.Getenv("SENTINELFLOW_GATEWAY_PERF_ALLOW_SHORT") != "1" {
		t.Fatalf("duration %s is below the frozen five-minute release gate; set SENTINELFLOW_GATEWAY_PERF_ALLOW_SHORT=1 only for a non-release harness check", duration)
	}
	if shortRun {
		t.Logf("NON-RELEASE harness check: duration=%s", duration)
	}

	origin := startGateOrigin(t)
	upstreamTransport := newGateOriginTransport(t, origin, gateWorkerCount)
	t.Cleanup(upstreamTransport.CloseIdleConnections)
	sink := &gateCountingSink{}
	metrics := observability.New(observability.Config{})
	handler, err := New(gateConfig(t), Dependencies{Sink: sink, Transport: upstreamTransport, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := startGateServer(t, handler)
	directClient, directTransport := gateClient(gateWorkerCount)
	gatewayClient, gatewayTransport := gateClient(gateWorkerCount)
	t.Cleanup(directTransport.CloseIdleConnections)
	t.Cleanup(gatewayTransport.CloseIdleConnections)

	direct := gateLoadTarget{name: "direct-origin", url: origin.url, client: directClient}
	proxied := gateLoadTarget{name: "gateway", url: gatewayServer.url, host: gatePublicHost, client: gatewayClient}
	warmupStart := time.Now().Add(250 * time.Millisecond)
	var warmupDirect, warmupGateway gateLoadResult
	var warmupGroup sync.WaitGroup
	warmupGroup.Add(2)
	go func() { defer warmupGroup.Done(); warmupDirect = runGateLoad(warmupStart, warmup, direct) }()
	go func() { defer warmupGroup.Done(); warmupGateway = runGateLoad(warmupStart, warmup, proxied) }()
	warmupGroup.Wait()
	assertGateLoad(t, warmupDirect, gateTargetRPS*0.99)
	assertGateLoad(t, warmupGateway, gateTargetRPS*0.99)
	if t.Failed() {
		t.FailNow()
	}

	sink.reset(gateSinkAccepted)
	runtime.GC()
	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	resources := startGateResourceSample()
	measurementStart := time.Now().Add(250 * time.Millisecond)
	var directResult, gatewayResult gateLoadResult
	var measurementGroup sync.WaitGroup
	measurementGroup.Add(2)
	go func() { defer measurementGroup.Done(); directResult = runGateLoad(measurementStart, duration, direct) }()
	go func() {
		defer measurementGroup.Done()
		gatewayResult = runGateLoad(measurementStart, duration, proxied)
	}()
	measurementGroup.Wait()
	resources.close()

	assertGateLoad(t, directResult, gateTargetRPS*0.99)
	assertGateLoad(t, gatewayResult, gateTargetRPS*0.99)
	if got := sink.accepted.Load(); got != uint64(gatewayResult.scheduled) {
		t.Errorf("healthy EventSink accepted=%d, want=%d", got, gatewayResult.scheduled)
	}
	if got := sink.dropped.Load(); got != 0 {
		t.Errorf("healthy EventSink dropped=%d, want=0", got)
	}
	healthyAccepted := sink.accepted.Load()
	addedP95 := gatewayResult.p95() - directResult.p95()
	if addedP95 < 0 {
		addedP95 = 0
	}
	t.Logf("proxy-added p95=%s (gateway=%s direct=%s limit=%s)", addedP95, gatewayResult.p95(), directResult.p95(), gateLatencyLimit)
	if addedP95 > gateLatencyLimit {
		t.Errorf("proxy-added p95 %s exceeds %s", addedP95, gateLatencyLimit)
	}

	if peak := gatewayServer.connections.peak.Load(); peak > gateWorkerCount {
		t.Errorf("Gateway peak connections=%d, bounded maximum=%d", peak, gateWorkerCount)
	}
	if peak := origin.connections.peak.Load(); peak > gateWorkerCount*2 {
		t.Errorf("origin peak connections=%d, bounded maximum=%d", peak, gateWorkerCount*2)
	}
	peakHeap := resources.peakHeap.Load()
	if peakHeap > memoryBefore.HeapInuse+gateHeapDeltaLimit {
		t.Errorf("heap growth exceeded bound: before=%d peak=%d limit_delta=%d", memoryBefore.HeapInuse, peakHeap, gateHeapDeltaLimit)
	}
	t.Logf("resources: heap_before=%d heap_peak=%d heap_delta=%d goroutines_peak=%d gateway_connections_peak=%d origin_connections_peak=%d",
		memoryBefore.HeapInuse, peakHeap, int64(peakHeap)-int64(memoryBefore.HeapInuse),
		resources.peakGoroutines.Load(), gatewayServer.connections.peak.Load(), origin.connections.peak.Load())

	sink.reset(gateSinkDropped)
	// Measure the direct origin concurrently with the outage path. Comparing
	// different wall-clock phases would misattribute host scheduling or GC
	// variance to the EventSink failure instead of measuring proxy overhead.
	outageStart := time.Now().Add(250 * time.Millisecond)
	var outageDirectResult, outageResult gateLoadResult
	var outageGroup sync.WaitGroup
	outageGroup.Add(2)
	go func() {
		defer outageGroup.Done()
		outageDirectResult = runGateLoad(outageStart, outageDuration, direct)
	}()
	go func() {
		defer outageGroup.Done()
		outageResult = runGateLoad(outageStart, outageDuration, gateLoadTarget{
			name: "gateway-event-sink-outage", url: gatewayServer.url, host: gatePublicHost, client: gatewayClient,
		})
	}()
	outageGroup.Wait()
	assertGateLoad(t, outageDirectResult, gateTargetRPS*0.99)
	assertGateLoad(t, outageResult, gateTargetRPS*0.99)
	if got := sink.accepted.Load(); got != 0 {
		t.Errorf("outage EventSink accepted=%d, want=0", got)
	}
	if got := sink.dropped.Load(); got != uint64(outageResult.scheduled) {
		t.Errorf("outage EventSink visible drops=%d, want=%d", got, outageResult.scheduled)
	}
	outageDropped := sink.dropped.Load()
	outageAddedP95 := outageResult.p95() - outageDirectResult.p95()
	if outageAddedP95 < 0 {
		outageAddedP95 = 0
	}
	if outageAddedP95 > gateLatencyLimit {
		t.Errorf("EventSink outage proxy-added p95=%s (gateway=%s direct=%s) exceeded %s",
			outageAddedP95, outageResult.p95(), outageDirectResult.p95(), gateLatencyLimit)
	}

	reference := "development"
	if !shortRun {
		reference = "five-minute"
	}
	t.Logf("GATE_RESULT mode=%s duration=%s rps=%d direct_p95_us=%s gateway_p95_us=%s added_p95_us=%s outage_direct_p95_us=%s outage_gateway_p95_us=%s outage_added_p95_us=%s accepted=%s dropped=%s",
		reference,
		duration,
		gateTargetRPS,
		strconv.FormatInt(directResult.p95().Microseconds(), 10),
		strconv.FormatInt(gatewayResult.p95().Microseconds(), 10),
		strconv.FormatInt(addedP95.Microseconds(), 10),
		strconv.FormatInt(outageDirectResult.p95().Microseconds(), 10),
		strconv.FormatInt(outageResult.p95().Microseconds(), 10),
		strconv.FormatInt(outageAddedP95.Microseconds(), 10),
		fmt.Sprint(healthyAccepted),
		fmt.Sprint(outageDropped),
	)
}
