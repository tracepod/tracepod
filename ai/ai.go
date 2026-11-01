// Package ai is an optional, provider-agnostic LLM client for the CLI's
// helpers. It is inert unless explicitly configured: New with an empty or
// "off" provider returns a provider whose Complete always fails with
// ErrDisabled and never touches the network.
//
// The package ships:
//
//   - a small Provider interface and Request/Response types;
//   - an OpenAI-compatible adapter (vLLM, Ollama, LiteLLM, OpenAI-style
//     gateways) built on net/http only;
//   - JSON helpers: CompleteJSON validates a model response against an
//     optional JSON Schema plus a caller-supplied check, with one retry;
//   - Redact / WithRedaction to scrub secrets from prompts.
//
// The Anthropic adapter (Anthropic API, Amazon Bedrock, Google Vertex AI)
// lives in the sub-package ai/anthropic so that its SDK dependencies are only
// linked into binaries that import it. Import it for its side effect to make
// New accept the "anthropic", "bedrock" and "vertex" providers:
//
//	import _ "github.com/tracepod/tracepod/ai/anthropic"
//
// Models are only ever asked to choose among candidates the caller computed
// deterministically (see ai/candidates); callers must validate every response.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Tier selects a model class.
type Tier string

const (
	// TierFast is for classification and selection.
	TierFast Tier = "fast"
	// TierStrong is for diagnosis.
	TierStrong Tier = "strong"
)

// Provider names accepted by Config.Provider.
const (
	ProviderOff              = "off"
	ProviderOpenAICompatible = "openai-compatible"
	ProviderAnthropic        = "anthropic"
	ProviderBedrock          = "bedrock"
	ProviderVertex           = "vertex"
)

// Structured-output modes for Config.StructuredOutput.
const (
	StructuredAuto = "auto"
	StructuredOn   = "on"
	StructuredOff  = "off"
)

// Defaults.
const (
	DefaultMaxTokens     = 2048
	DefaultTimeout       = 60 * time.Second
	DefaultMaxInputBytes = 200 * 1024
)

// Message is one conversation turn. Role is "user" or "assistant".
type Message struct {
	Role string
	Text string
}

// Request is a single completion request.
type Request struct {
	Tier     Tier
	System   string
	Messages []Message
	// Schema is an optional JSON Schema the output must satisfy.
	Schema     json.RawMessage
	SchemaName string
	// MaxTokens defaults to DefaultMaxTokens.
	MaxTokens int
}

// Response is a completed model answer.
type Response struct {
	Text         string
	Model        string
	StopReason   string
	InputTokens  int
	OutputTokens int
}

// Provider is a language-model backend.
type Provider interface {
	Complete(ctx context.Context, req Request) (Response, error)
	// Name is one of the Provider* constants.
	Name() string
}

// Sentinel errors. Use errors.Is.
var (
	// ErrDisabled: no provider is configured.
	ErrDisabled = errors.New("ai: disabled")
	// ErrRefused: the model declined to answer; treat as "no suggestion".
	ErrRefused = errors.New("ai: model refused")
	// ErrInvalidOutput: the response did not parse or validate, after a retry.
	ErrInvalidOutput = errors.New("ai: invalid model output")
	// ErrTruncated: the response hit the output token limit.
	ErrTruncated = errors.New("ai: response truncated")
)

// APIError is a non-success HTTP answer from a provider.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ai: provider returned HTTP %d: %s", e.StatusCode, e.Message)
}

// Retryable reports whether the failure is transient (429 or 5xx).
func (e *APIError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// Config configures New. The zero value means "off".
type Config struct {
	// Provider is one of the Provider* constants; empty means off.
	Provider string
	// BaseURL is the OpenAI-compatible endpoint, e.g. http://host:11434/v1
	// (a bare http://host:11434 gets /v1 appended). For the anthropic
	// provider it optionally overrides the API base URL (gateways).
	BaseURL string
	// APIKey is optional for every provider. For anthropic the SDK falls back
	// to its default credential chain; for bedrock and vertex the AWS / Google
	// default chains are used. The key is never logged or included in errors.
	APIKey string
	// ModelFast and ModelStrong are model identifiers. Anthropic-family
	// providers default to claude-haiku-5-5 / claude-sonnet-5-5 (with an
	// "anthropic." prefix on Bedrock); the OpenAI-compatible provider has no
	// default and requires ModelFast (ModelStrong falls back to ModelFast).
	ModelFast   string
	ModelStrong string
	// Region and ProjectID locate Bedrock (Region) and Vertex (both).
	Region    string
	ProjectID string
	// StructuredOutput is "auto" (default), "on" or "off".
	StructuredOutput string
	// Timeout bounds each Complete call. Default 60s.
	Timeout time.Duration
	// MaxInputBytes caps the combined prompt size; larger inputs are
	// truncated from the middle with a marker. Default 200 KB.
	MaxInputBytes int
	// HTTPClient is used by the OpenAI-compatible adapter. Default: a
	// dedicated client with no proxy-specific behaviour beyond the standard.
	HTTPClient *http.Client
}

// WithDefaults returns c with defaults filled in.
func (c Config) WithDefaults() Config {
	if c.Provider == "" {
		c.Provider = ProviderOff
	}
	if c.StructuredOutput == "" {
		c.StructuredOutput = StructuredAuto
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxInputBytes <= 0 {
		c.MaxInputBytes = DefaultMaxInputBytes
	}
	return c
}

// Factory builds a provider from a Config whose Provider field it handles.
type Factory func(cfg Config) (Provider, error)

var (
	regMu     sync.RWMutex
	factories = map[string]Factory{}
)

// Register installs a factory for a provider name. It is used by adapter
// sub-packages from init and panics on duplicates.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := factories[name]; dup {
		panic("ai: duplicate provider registration: " + name)
	}
	factories[name] = f
}

// New builds the provider selected by cfg.Provider. "off" (or empty) yields a
// provider that returns ErrDisabled without any network access.
func New(cfg Config) (Provider, error) {
	cfg = cfg.WithDefaults()
	switch cfg.Provider {
	case ProviderOff:
		return noop{}, nil
	case ProviderOpenAICompatible:
		return newOpenAI(cfg)
	case ProviderAnthropic, ProviderBedrock, ProviderVertex:
		regMu.RLock()
		f := factories[cfg.Provider]
		regMu.RUnlock()
		if f == nil {
			return nil, fmt.Errorf("ai: provider %q requires importing github.com/tracepod/tracepod/ai/anthropic", cfg.Provider)
		}
		return f(cfg)
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", cfg.Provider)
	}
}

type noop struct{}

func (noop) Complete(context.Context, Request) (Response, error) {
	return Response{}, ErrDisabled
}
func (noop) Name() string { return ProviderOff }

// ModelFor returns the model id for the request tier, applying fallbacks:
// strong falls back to fast.
func (c Config) ModelFor(t Tier) string {
	if t == TierStrong && c.ModelStrong != "" {
		return c.ModelStrong
	}
	if c.ModelFast != "" {
		return c.ModelFast
	}
	return c.ModelStrong
}

// Prepare normalises a request for sending: default MaxTokens and the input
// size cap. It does not mutate req's slices.
func (c Config) Prepare(req Request) Request {
	if req.MaxTokens <= 0 {
		req.MaxTokens = DefaultMaxTokens
	}
	limit := c.MaxInputBytes
	if limit <= 0 {
		limit = DefaultMaxInputBytes
	}
	total := len(req.System)
	for _, m := range req.Messages {
		total += len(m.Text)
	}
	if total <= limit {
		return req
	}
	// Shrink the largest messages proportionally; system prompts stay intact
	// unless they alone exceed the budget.
	budget := limit - len(req.System)
	if budget < 1024 {
		budget = 1024
	}
	msgTotal := total - len(req.System)
	msgs := make([]Message, len(req.Messages))
	for i, m := range req.Messages {
		share := int(float64(budget) * float64(len(m.Text)) / float64(max(msgTotal, 1)))
		msgs[i] = Message{Role: m.Role, Text: TruncateMiddle(m.Text, share)}
	}
	req.Messages = msgs
	return req
}

// TruncateMiddle shortens s to about limit bytes by dropping its middle and
// inserting a marker. Head and tail are kept because errors tend to appear at
// both ends of a log.
func TruncateMiddle(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	const marker = "\n[... truncated ...]\n"
	if limit <= len(marker)+2 {
		return marker
	}
	keep := limit - len(marker)
	head := keep / 2
	tail := keep - head
	// Avoid cutting UTF-8 sequences.
	for head > 0 && !runeStart(s[head]) {
		head--
	}
	start := len(s) - tail
	for start < len(s) && !runeStart(s[start]) {
		start++
	}
	return s[:head] + marker + s[start:]
}

func runeStart(b byte) bool { return b&0xC0 != 0x80 }
