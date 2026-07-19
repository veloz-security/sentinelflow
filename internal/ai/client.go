package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ClientConfig struct {
	APIKey          string
	BaseURL         string
	RateCardVersion string
	RequestTimeout  time.Duration
	MaxAttempts     int
	Artifacts       Artifacts
	RoundTripper    http.RoundTripper
	Clock           Clock
	Budget          BudgetGate
}

type credential struct{ value string }

func (credential) String() string   { return "[REDACTED]" }
func (credential) GoString() string { return "[REDACTED]" }

type Client struct {
	apiKey          credential
	endpoint        url.URL
	rateCardVersion string
	artifacts       Artifacts
	transport       http.RoundTripper
	clock           Clock
	budget          BudgetGate
	semaphore       chan struct{}
	requestTimeout  time.Duration
	maxAttempts     int
	identity        ProviderIdentity
}

var rateCardVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func NewClient(config ClientConfig) (*Client, error) {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = RequestTimeout
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 2
	}
	if !validCredential(config.APIKey) || !rateCardVersionPattern.MatchString(config.RateCardVersion) ||
		config.RequestTimeout <= 0 || config.RequestTimeout > RequestTimeout ||
		config.MaxAttempts < 1 || config.MaxAttempts > 2 ||
		config.Budget == nil || len(config.Artifacts.inputSchema) == 0 || len(config.Artifacts.systemPrompt) == 0 || len(config.Artifacts.outputSchema) == 0 {
		return nil, &Failure{Reason: FailureConfiguration}
	}
	base := config.BaseURL
	if base == "" {
		base = "https://api.openai.com"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, &Failure{Reason: FailureConfiguration}
	}
	parsed.Path = ResponsesPath
	parsed.RawPath = ""
	transport := config.RoundTripper
	if transport == nil {
		transport = http.DefaultTransport
	}
	clock := config.Clock
	if clock == nil {
		clock = realClock{}
	}
	identity, ok := NewOpenAIResponsesIdentity(config.RateCardVersion)
	if !ok {
		return nil, &Failure{Reason: FailureConfiguration}
	}
	return &Client{
		apiKey:          credential{value: config.APIKey},
		endpoint:        *parsed,
		rateCardVersion: config.RateCardVersion,
		artifacts:       config.Artifacts,
		transport:       transport,
		clock:           clock,
		budget:          config.Budget,
		semaphore:       make(chan struct{}, MaxConcurrency),
		requestTimeout:  config.RequestTimeout,
		maxAttempts:     config.MaxAttempts,
		identity:        identity,
	}, nil
}

func (c *Client) Identity() ProviderIdentity {
	if c == nil {
		return ProviderIdentity{}
	}
	return c.identity
}

func validCredential(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (c *Client) Analyze(ctx context.Context, input []byte) (Result, error) {
	if ctx == nil {
		return Result{}, &Failure{Reason: FailureConfiguration}
	}
	validated, err := validateInput(input)
	if err != nil {
		return Result{}, err
	}
	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return Result{}, contextFailure(ctx.Err(), 0)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, contextFailure(err, 0)
	}

	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		result, failure := c.attempt(ctx, validated, attempt)
		if failure == nil {
			result.Attempts = attempt
			return result, nil
		}
		failure.Attempts = attempt
		if attempt == c.maxAttempts || !retryableStatus(failure.StatusCode) {
			return Result{}, failure
		}
		if err := c.clock.Sleep(ctx, retryDelay); err != nil {
			return Result{}, contextFailure(err, attempt)
		}
	}
	return Result{}, &Failure{Reason: FailureServerError, Attempts: c.maxAttempts}
}

func (c *Client) attempt(parent context.Context, input validatedInput, attempt int) (Result, *Failure) {
	reservation, err := c.budget.Reserve(parent, BudgetRequest{
		Model:              Model,
		RateCardVersion:    c.rateCardVersion,
		MaxInputTokenUnits: MaxInputBytes,
		MaxOutputTokens:    MaxOutputTokens,
		ReservedAt:         c.clock.Now().UTC(),
	})
	if err != nil {
		if parent.Err() != nil {
			return Result{}, contextFailure(parent.Err(), attempt)
		}
		if errors.Is(err, ErrBudgetExhausted) {
			return Result{}, &Failure{Reason: FailureBudgetExhausted, Attempts: attempt}
		}
		return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
	}
	if reservation == nil {
		return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
	}

	ctx, cancel := context.WithTimeout(parent, c.requestTimeout)
	defer cancel()
	body, err := c.requestBody(input.bytes)
	if err != nil {
		_ = settleReservation(parent, reservation, Usage{}, true)
		return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		_ = settleReservation(parent, reservation, Usage{}, true)
		return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey.value)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "sentinelflow/0.1")

	response, err := c.transport.RoundTrip(request)
	if err != nil {
		if settleErr := settleReservation(parent, reservation, Usage{}, true); settleErr != nil {
			return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
		}
		return Result{}, transportFailure(ctx, err, attempt)
	}
	if response == nil || response.Body == nil {
		if settleErr := settleReservation(parent, reservation, Usage{}, true); settleErr != nil {
			return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
		}
		return Result{}, &Failure{Reason: FailureNetworkError, Attempts: attempt}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if settleErr := settleReservation(parent, reservation, Usage{}, true); settleErr != nil {
			return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
		}
		return Result{}, statusFailure(response.StatusCode, attempt)
	}

	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		if settleErr := settleReservation(parent, reservation, Usage{}, true); settleErr != nil {
			return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
		}
		return Result{}, transportFailure(ctx, readErr, attempt)
	}
	if len(responseBytes) > maxResponseBytes {
		if settleErr := settleReservation(parent, reservation, Usage{}, true); settleErr != nil {
			return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
		}
		return Result{}, &Failure{Reason: FailureSchemaInvalid, Attempts: attempt}
	}
	result, failure := c.parseResponse(responseBytes, input)
	fullCharge := failure != nil || !result.Usage.Trusted
	if settleErr := settleReservation(parent, reservation, result.Usage, fullCharge); settleErr != nil {
		return Result{}, &Failure{Reason: FailureConfiguration, Attempts: attempt}
	}
	if failure != nil {
		failure.Attempts = attempt
		return Result{}, failure
	}
	result.InputDigest = input.digest
	result.InputSchemaDigest = c.artifacts.inputSchemaDigest
	result.PromptDigest = c.artifacts.promptDigest
	result.OutputSchemaDigest = c.artifacts.outputSchemaDigest
	return result, nil
}

func settleReservation(parent context.Context, reservation BudgetReservation, usage Usage, fullCharge bool) error {
	settlementContext, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	return reservation.Settle(settlementContext, usage, fullCharge)
}

type responseRequest struct {
	Model           string            `json:"model"`
	Input           []responseMessage `json:"input"`
	Reasoning       reasoning         `json:"reasoning"`
	Store           bool              `json:"store"`
	MaxOutputTokens int               `json:"max_output_tokens"`
	Text            responseText      `json:"text"`
}

type reasoning struct {
	Effort string `json:"effort"`
}

type responseMessage struct {
	Role    string            `json:"role"`
	Content []responseContent `json:"content"`
}

type responseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type responseText struct {
	Format responseFormat `json:"format"`
}

type responseFormat struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

func (c *Client) requestBody(input []byte) ([]byte, error) {
	return json.Marshal(responseRequest{
		Model: Model,
		Input: []responseMessage{
			{Role: "system", Content: []responseContent{{Type: "input_text", Text: string(c.artifacts.systemPrompt)}}},
			{Role: "user", Content: []responseContent{{Type: "input_text", Text: string(input)}}},
		},
		Reasoning:       reasoning{Effort: ReasoningEffort},
		Store:           false,
		MaxOutputTokens: MaxOutputTokens,
		Text: responseText{Format: responseFormat{
			Type:   "json_schema",
			Name:   "sentinelflow_analysis_v1",
			Strict: true,
			Schema: json.RawMessage(c.artifacts.outputSchema),
		}},
	})
}

type apiResponse struct {
	ID                string             `json:"id"`
	Status            string             `json:"status"`
	IncompleteDetails *incompleteDetails `json:"incomplete_details"`
	Output            []apiOutput        `json:"output"`
	Usage             *apiUsage          `json:"usage"`
}

type incompleteDetails struct {
	Reason string `json:"reason"`
}

type apiOutput struct {
	Type    string       `json:"type"`
	Status  string       `json:"status"`
	Content []apiContent `json:"content"`
}

type apiContent struct {
	Type    string `json:"type"`
	Text    string `json:"text"`
	Refusal string `json:"refusal"`
}

type apiUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	InputDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

func (c *Client) parseResponse(data []byte, input validatedInput) (Result, *Failure) {
	if validateJSONDocument(data, true) != nil {
		return Result{}, &Failure{Reason: FailureSchemaInvalid}
	}
	var response apiResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return Result{}, &Failure{Reason: FailureSchemaInvalid}
	}
	if response.Status == "incomplete" || response.IncompleteDetails != nil {
		return Result{}, &Failure{Reason: FailureIncomplete}
	}
	if response.Status != "completed" {
		return Result{}, &Failure{Reason: FailureIncomplete}
	}
	var outputText string
	count := 0
	for _, output := range response.Output {
		for _, content := range output.Content {
			switch content.Type {
			case "refusal":
				return Result{}, &Failure{Reason: FailureRefused}
			case "output_text":
				count++
				outputText += content.Text
			}
		}
	}
	if count == 0 || outputText == "" {
		return Result{}, &Failure{Reason: FailureSchemaInvalid}
	}
	if err := validateOutput([]byte(outputText), c.artifacts.outputSchema, input); err != nil {
		failure, ok := FailureOf(err)
		if !ok {
			return Result{}, &Failure{Reason: FailureSchemaInvalid}
		}
		return Result{}, failure
	}

	usage := Usage{}
	if response.Usage != nil && response.Usage.InputTokens > 0 && response.Usage.OutputTokens > 0 &&
		response.Usage.InputDetails.CachedTokens >= 0 && response.Usage.InputDetails.CachedTokens <= response.Usage.InputTokens {
		usage = Usage{
			InputTokens:       response.Usage.InputTokens,
			CachedInputTokens: response.Usage.InputDetails.CachedTokens,
			OutputTokens:      response.Usage.OutputTokens,
			Trusted:           true,
		}
	}
	return Result{ResponseID: response.ID, Output: []byte(outputText), Usage: usage}, nil
}

func retryableStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusConflict || status == http.StatusTooManyRequests || status >= 500 && status <= 599
}

func statusFailure(status, attempt int) *Failure {
	failure := &Failure{StatusCode: status, Attempts: attempt}
	switch {
	case status == http.StatusRequestTimeout:
		failure.Reason = FailureHTTP408
	case status == http.StatusConflict:
		failure.Reason = FailureHTTP409
	case status == http.StatusTooManyRequests:
		failure.Reason = FailureRateLimited
	case status >= 500 && status <= 599:
		failure.Reason = FailureServerError
	default:
		failure.Reason = FailureConfiguration
	}
	return failure
}

func transportFailure(ctx context.Context, err error, attempt int) *Failure {
	if ctx.Err() != nil {
		return contextFailure(ctx.Err(), attempt)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Failure{Reason: FailureTimeout, Attempts: attempt}
	}
	if errors.Is(err, context.Canceled) {
		return &Failure{Reason: FailureCancelled, Attempts: attempt}
	}
	return &Failure{Reason: FailureNetworkError, Attempts: attempt}
}

func contextFailure(err error, attempts int) *Failure {
	if errors.Is(err, context.DeadlineExceeded) {
		return &Failure{Reason: FailureTimeout, Attempts: attempts}
	}
	return &Failure{Reason: FailureCancelled, Attempts: attempts}
}

func (c *Client) String() string {
	return fmt.Sprintf("OpenAIClient{model:%s endpoint:%s api_key:%s}", Model, c.endpoint.Redacted(), c.apiKey)
}

func (c *Client) GoString() string { return c.String() }
