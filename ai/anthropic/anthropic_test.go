package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/tracepod/tracepod/ai"
)

type server struct {
	*httptest.Server
	mu      sync.Mutex
	bodies  []map[string]any
	headers []http.Header
	calls   atomic.Int32
}

func newServer(t *testing.T, h func(call int, w http.ResponseWriter)) *server {
	t.Helper()
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		s.mu.Lock()
		s.bodies = append(s.bodies, b)
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		h(int(s.calls.Add(1)), w)
	}))
	t.Cleanup(s.Close)
	return s
}

func reply(w http.ResponseWriter, text, stop string) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(map[string]any{
		"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
		"content":     []any{map[string]any{"type": "text", "text": text}},
		"stop_reason": stop, "stop_sequence": nil,
		"usage": map[string]any{"input_tokens": 11, "output_tokens": 4},
	})
	_, _ = w.Write(b)
}

func newProvider(t *testing.T, s *server, mut func(*ai.Config)) ai.Provider {
	t.Helper()
	cfg := ai.Config{Provider: ai.ProviderAnthropic, APIKey: "test-key", BaseURL: s.URL}
	if mut != nil {
		mut(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Disable SDK retries so error tests are fast and call counts exact.
	p.(*provider).api = retryless(s.URL)
	return p
}

func retryless(base string) messageAPI {
	c := sdk.NewClient(option.WithBaseURL(base), option.WithAPIKey("test-key"), option.WithMaxRetries(0))
	return &c.Messages
}

var schema = json.RawMessage(`{"type":"object","properties":{"paths":{"type":"array","items":{"type":"string"}}},"required":["paths"],"additionalProperties":false}`)

func TestCompleteEndTurn(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter) { reply(w, `{"paths":["/a"]}`, "end_turn") })
	p := newProvider(t, s, nil)
	if p.Name() != "anthropic" {
		t.Fatal(p.Name())
	}
	resp, err := p.Complete(context.Background(), ai.Request{
		Tier: ai.TierStrong, System: "sys", Schema: schema,
		Messages: []ai.Message{{Role: "user", Text: "q"}, {Role: "assistant", Text: "a"}, {Role: "user", Text: "r"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != `{"paths":["/a"]}` || resp.StopReason != "end_turn" || resp.InputTokens != 11 || resp.OutputTokens != 4 || resp.Model == "" {
		t.Fatalf("resp = %+v", resp)
	}
	b := s.bodies[0]
	if b["model"] != "claude-sonnet-5-5" || b["max_tokens"].(float64) != 2048 {
		t.Fatalf("body = %v", b)
	}
	for _, forbidden := range []string{"temperature", "tool_choice", "tools", "top_p", "top_k"} {
		if _, ok := b[forbidden]; ok {
			t.Errorf("%s must not be sent", forbidden)
		}
	}
	oc := b["output_config"].(map[string]any)
	f := oc["format"].(map[string]any)
	if f["type"] != "json_schema" || f["schema"] == nil {
		t.Fatalf("output_config = %v", oc)
	}
	if _, ok := oc["effort"]; ok {
		t.Error("strong tier should not set effort")
	}
	msgs := b["messages"].([]any)
	if len(msgs) != 3 || msgs[1].(map[string]any)["role"] != "assistant" {
		t.Fatalf("messages = %v", msgs)
	}
	if sys := b["system"].([]any)[0].(map[string]any)["text"]; sys != "sys" {
		t.Fatalf("system = %v", b["system"])
	}
}

func TestFastTierUsesHaikuAndLowEffort(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter) { reply(w, "ok", "end_turn") })
	p := newProvider(t, s, nil)
	if _, err := p.Complete(context.Background(), ai.Request{Tier: ai.TierFast, Messages: []ai.Message{{Role: "user", Text: "q"}}}); err != nil {
		t.Fatal(err)
	}
	b := s.bodies[0]
	if b["model"] != "claude-haiku-5-5" || b["output_config"].(map[string]any)["effort"] != "low" {
		t.Fatalf("body = %v", b)
	}
	if _, ok := b["output_config"].(map[string]any)["format"]; ok {
		t.Error("format sent without schema")
	}
}

func TestStructuredOff(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter) { reply(w, "{}", "end_turn") })
	p := newProvider(t, s, func(c *ai.Config) { c.StructuredOutput = ai.StructuredOff })
	if _, err := p.Complete(context.Background(), ai.Request{Tier: ai.TierStrong, Schema: schema, System: "s"}); err != nil {
		t.Fatal(err)
	}
	b := s.bodies[0]
	if oc, ok := b["output_config"]; ok && oc.(map[string]any)["format"] != nil {
		t.Fatalf("format sent: %v", oc)
	}
	if sys := b["system"].([]any)[0].(map[string]any)["text"].(string); !strings.Contains(sys, "JSON Schema") {
		t.Fatalf("schema missing from prompt: %s", sys)
	}
}

func TestRefusalAndMaxTokens(t *testing.T) {
	for stop, want := range map[string]error{"refusal": ai.ErrRefused, "max_tokens": ai.ErrTruncated} {
		s := newServer(t, func(_ int, w http.ResponseWriter) { reply(w, "partial", stop) })
		p := newProvider(t, s, nil)
		resp, err := p.Complete(context.Background(), ai.Request{Messages: []ai.Message{{Role: "user", Text: "q"}}})
		if !errors.Is(err, want) || resp.StopReason != stop {
			t.Errorf("%s: err=%v resp=%+v", stop, err, resp)
		}
	}
}

func TestRefusalIsNotRetriedByCompleteJSON(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter) { reply(w, "", "refusal") })
	p := newProvider(t, s, nil)
	_, _, err := ai.CompleteJSON[map[string]any](context.Background(), p, ai.Request{Schema: schema, Messages: []ai.Message{{Role: "user", Text: "q"}}}, nil)
	if !errors.Is(err, ai.ErrRefused) || s.calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, s.calls.Load())
	}
}

func TestCompleteJSONRetryThroughSDK(t *testing.T) {
	s := newServer(t, func(call int, w http.ResponseWriter) {
		if call == 1 {
			reply(w, `{"paths":"oops"}`, "end_turn")
			return
		}
		reply(w, `{"paths":["/a"]}`, "end_turn")
	})
	p := newProvider(t, s, nil)
	type out struct{ Paths []string }
	v, _, err := ai.CompleteJSON[out](context.Background(), p, ai.Request{Schema: schema, Messages: []ai.Message{{Role: "user", Text: "q"}}}, nil)
	if err != nil || len(v.Paths) != 1 || s.calls.Load() != 2 {
		t.Fatalf("v=%+v err=%v calls=%d", v, err, s.calls.Load())
	}
}

func TestHTTPErrors(t *testing.T) {
	for _, tc := range []struct {
		status    int
		retryable bool
	}{{400, false}, {401, false}, {429, true}, {500, true}, {529, true}} {
		s := newServer(t, func(_ int, w http.ResponseWriter) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"x","message":"bad thing"}}`))
		})
		p := newProvider(t, s, nil)
		_, err := p.Complete(context.Background(), ai.Request{Messages: []ai.Message{{Role: "user", Text: "q"}}})
		var apiErr *ai.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Retryable() != tc.retryable ||
			!strings.Contains(apiErr.Message, "bad thing") {
			t.Errorf("%d: err=%v", tc.status, err)
		}
		if strings.Contains(err.Error(), "test-key") {
			t.Error("error leaks key")
		}
	}
}

func TestSDKRetriesTransientErrors(t *testing.T) {
	s := newServer(t, func(call int, w http.ResponseWriter) {
		if call == 1 {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"x"}}`))
			return
		}
		reply(w, "ok", "end_turn")
	})
	// Default client (SDK retries enabled), via New with a gateway BaseURL.
	p, err := New(ai.Config{Provider: ai.ProviderAnthropic, APIKey: "k", BaseURL: s.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), ai.Request{Messages: []ai.Message{{Role: "user", Text: "q"}}}); err != nil {
		t.Fatal(err)
	}
	if s.calls.Load() != 2 {
		t.Fatalf("calls = %d", s.calls.Load())
	}
	if got := s.headers[0]; got.Get("Authorization") != "Bearer k" {
		t.Fatalf("headers = %v", got)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	block := make(chan struct{})
	s := newServer(t, func(_ int, w http.ResponseWriter) { <-block })
	defer close(block)
	p := newProvider(t, s, func(c *ai.Config) { c.Timeout = 100 * time.Millisecond })
	req := ai.Request{Messages: []ai.Message{{Role: "user", Text: "q"}}}
	if _, err := p.Complete(context.Background(), req); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Complete(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err = %v", err)
	}
}

func TestBadRole(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter) { reply(w, "ok", "end_turn") })
	p := newProvider(t, s, nil)
	if _, err := p.Complete(context.Background(), ai.Request{Messages: []ai.Message{{Role: "tool", Text: "q"}}}); err == nil || s.calls.Load() != 0 {
		t.Fatalf("err=%v calls=%d", err, s.calls.Load())
	}
}

func TestDefaultsAndRegistration(t *testing.T) {
	// Importing this package registers all three providers with ai.New.
	p, err := ai.New(ai.Config{Provider: ai.ProviderAnthropic, APIKey: "k"})
	if err != nil || p.Name() != "anthropic" {
		t.Fatalf("p=%v err=%v", p, err)
	}
	ap := p.(*provider)
	if ap.cfg.ModelFor(ai.TierFast) != DefaultFast || ap.cfg.ModelFor(ai.TierStrong) != DefaultStrong {
		t.Fatalf("models = %q %q", ap.cfg.ModelFast, ap.cfg.ModelStrong)
	}
	// Explicit models win.
	p, _ = ai.New(ai.Config{Provider: ai.ProviderAnthropic, APIKey: "k", ModelFast: "custom"})
	if p.(*provider).cfg.ModelFor(ai.TierFast) != "custom" {
		t.Fatal("explicit model ignored")
	}
}

func TestBedrockDefaultsAndStaticCredsEnv(t *testing.T) {
	// Supply credentials through the standard environment chain; no network.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secretexample")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	p, err := ai.New(ai.Config{Provider: ai.ProviderBedrock, Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	ap := p.(*provider)
	if p.Name() != "bedrock" || ap.cfg.ModelFast != "anthropic.claude-haiku-5-5" || ap.cfg.ModelStrong != "anthropic.claude-sonnet-5-5" {
		t.Fatalf("name=%s models=%q %q", p.Name(), ap.cfg.ModelFast, ap.cfg.ModelStrong)
	}
}

func TestVertexRequiresRegion(t *testing.T) {
	if _, err := ai.New(ai.Config{Provider: ai.ProviderVertex}); err == nil {
		t.Fatal("want error")
	}
}

func TestVertexMissingCredentialsIsAnErrorNotAPanic(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/creds.json")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
	t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
	if _, err := ai.New(ai.Config{Provider: ai.ProviderVertex, Region: "us-east5", ProjectID: "p"}); err == nil {
		t.Fatal("want error")
	}
}
