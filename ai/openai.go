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
	"sync/atomic"
)

type openAI struct {
	cfg      Config
	endpoint string
	client   *http.Client
	// noFormat is set once an endpoint rejected response_format under "auto".
	noFormat atomic.Bool
}

var versionSuffix = regexp.MustCompile(`/v\d+$`)

func newOpenAI(cfg Config) (Provider, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("ai: openai-compatible provider requires BaseURL")
	}
	if cfg.ModelFast == "" && cfg.ModelStrong == "" {
		return nil, errors.New("ai: openai-compatible provider requires ModelFast")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("ai: invalid BaseURL %q", cfg.BaseURL)
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if !versionSuffix.MatchString(base) {
		base += "/v1"
	}
	switch cfg.StructuredOutput {
	case StructuredAuto, StructuredOn, StructuredOff:
	default:
		return nil, fmt.Errorf("ai: invalid StructuredOutput %q", cfg.StructuredOutput)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	return &openAI{cfg: cfg, endpoint: base + "/chat/completions", client: client}, nil
}

func (o *openAI) Name() string { return ProviderOpenAICompatible }

type oaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaRequest struct {
	Model          string         `json:"model"`
	Messages       []oaMessage    `json:"messages"`
	MaxTokens      int            `json:"max_tokens"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
}

type oaResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content any    `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (o *openAI) Complete(ctx context.Context, req Request) (Response, error) {
	req = o.cfg.Prepare(req)
	ctx, cancel := context.WithTimeout(ctx, o.cfg.Timeout)
	defer cancel()

	useFormat := len(req.Schema) > 0 && o.cfg.StructuredOutput != StructuredOff &&
		(o.cfg.StructuredOutput != StructuredAuto || !o.noFormat.Load())
	resp, err := o.do(ctx, req, useFormat)
	var apiErr *APIError
	if useFormat && o.cfg.StructuredOutput == StructuredAuto && errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusBadRequest &&
		strings.Contains(strings.ToLower(apiErr.Message), "response_format") {
		o.noFormat.Store(true)
		resp, err = o.do(ctx, req, false)
	}
	return resp, err
}

func (o *openAI) do(ctx context.Context, req Request, useFormat bool) (Response, error) {
	system := req.System
	if len(req.Schema) > 0 && !useFormat {
		system = strings.TrimSpace(system + "\n\n" + SchemaInstruction(req.Schema))
	}
	body := oaRequest{Model: o.cfg.ModelFor(req.Tier), MaxTokens: req.MaxTokens}
	if system != "" {
		body.Messages = append(body.Messages, oaMessage{Role: "system", Content: system})
	}
	for _, m := range req.Messages {
		body.Messages = append(body.Messages, oaMessage{Role: m.Role, Content: m.Text})
	}
	if useFormat {
		name := req.SchemaName
		if name == "" {
			name = "response"
		}
		body.ResponseFormat = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   name,
				"schema": json.RawMessage(req.Schema),
				"strict": true,
			},
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	if o.cfg.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)
	}
	hresp, err := o.client.Do(hreq)
	if err != nil {
		// Transport errors can embed the URL but never headers; safe to wrap.
		return Response{}, fmt.Errorf("ai: openai-compatible request failed: %w", err)
	}
	defer hresp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(hresp.Body, 8<<20))
	if err != nil {
		return Response{}, fmt.Errorf("ai: reading response: %w", err)
	}
	if hresp.StatusCode < 200 || hresp.StatusCode > 299 {
		return Response{}, &APIError{StatusCode: hresp.StatusCode, Message: ErrorMessage(raw)}
	}
	var out oaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("ai: malformed response: %w", err)
	}
	if len(out.Choices) == 0 {
		return Response{}, errors.New("ai: response has no choices")
	}
	c := out.Choices[0]
	r := Response{
		Model:        out.Model,
		StopReason:   c.FinishReason,
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
	}
	if s, ok := c.Message.Content.(string); ok {
		r.Text = s
	}
	switch {
	case c.Message.Refusal != "" || c.FinishReason == "content_filter":
		return r, ErrRefused
	case c.FinishReason == "length":
		return r, ErrTruncated
	}
	return r, nil
}

// ErrorMessage extracts a short message from an error body without echoing
// large payloads.
func ErrorMessage(raw []byte) string {
	var e struct {
		Error any `json:"error"`
	}
	msg := ""
	if json.Unmarshal(raw, &e) == nil && e.Error != nil {
		switch v := e.Error.(type) {
		case string:
			msg = v
		case map[string]any:
			if m, ok := v["message"].(string); ok {
				msg = m
			}
		}
	}
	if msg == "" {
		msg = string(raw)
	}
	msg = strings.TrimSpace(msg)
	if len(msg) > 500 {
		msg = msg[:500] + "..."
	}
	return msg
}

// SchemaInstruction is the prompt text used when a schema cannot be sent via a
// native structured-output field.
func SchemaInstruction(schema json.RawMessage) string {
	return "Respond with a single JSON value and nothing else (no prose, no code fences) that conforms to this JSON Schema:\n" + string(schema)
}
