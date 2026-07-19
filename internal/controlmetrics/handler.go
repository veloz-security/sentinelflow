package controlmetrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const openMetricsContentType = "application/openmetrics-text; version=1.0.0; charset=utf-8"

type Collector interface {
	Collect(context.Context) ([]Sample, error)
}

func Handler(collector Collector, timeout time.Duration) (http.Handler, error) {
	if collector == nil || timeout < minimumScrapeTimeout || timeout > maximumScrapeTimeout {
		return nil, ErrInvalidConfiguration
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeError(writer, http.StatusMethodNotAllowed)
			return
		}
		if request.URL == nil || (request.URL.Path != "/metrics" && request.URL.Path != "/health") ||
			request.URL.RawPath != "" ||
			request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" ||
			request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
			writeError(writer, http.StatusNotFound)
			return
		}
		if request.URL.Path == "/health" {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "ok\n")
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), timeout)
		defer cancel()
		samples, err := collector.Collect(ctx)
		if err != nil {
			writeError(writer, http.StatusServiceUnavailable)
			return
		}
		payload, err := render(samples)
		if err != nil {
			writeError(writer, http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", openMetricsContentType)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(payload)
	}), nil
}

func render(samples []Sample) ([]byte, error) {
	if len(samples) == 0 || len(samples) > 512 {
		return nil, ErrInvalidSample
	}
	ordered := append([]Sample(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return sampleKey(ordered[i]) < sampleKey(ordered[j]) })
	var output bytes.Buffer
	lastName := ""
	lastKey := ""
	for _, sample := range ordered {
		if !validSample(sample) {
			return nil, ErrInvalidSample
		}
		key := sampleKey(sample)
		if key == lastKey {
			return nil, ErrInvalidSample
		}
		lastKey = key
		if sample.Name != lastName {
			fmt.Fprintf(&output, "# HELP %s Aggregate SentinelFlow control-plane state.\n", sample.Name)
			fmt.Fprintf(&output, "# TYPE %s gauge\n", sample.Name)
			lastName = sample.Name
		}
		output.WriteString(sample.Name)
		if sample.Label1Name != "" {
			fmt.Fprintf(&output, "{%s=%s", sample.Label1Name, strconv.Quote(sample.Label1Value))
			if sample.Label2Name != "" {
				fmt.Fprintf(&output, ",%s=%s", sample.Label2Name, strconv.Quote(sample.Label2Value))
			}
			output.WriteByte('}')
		}
		output.WriteByte(' ')
		output.WriteString(strconv.FormatFloat(sample.Value, 'g', -1, 64))
		output.WriteByte('\n')
	}
	output.WriteString("# EOF\n")
	return output.Bytes(), nil
}

func writeError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, strings.ToLower(http.StatusText(status))+"\n")
}
