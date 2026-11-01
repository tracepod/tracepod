package ai

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
)

func TestOffMakesNoNetworkCalls(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	http.DefaultTransport = failTransport{}

	for _, cfg := range []Config{
		{},
		{Provider: ProviderOff},
		{Provider: ProviderOff, BaseURL: srv.URL, APIKey: "k", ModelFast: "m"},
	} {
		p, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name() != ProviderOff {
			t.Fatalf("name = %q", p.Name())
		}
		if _, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}}); !errors.Is(err, ErrDisabled) {
			t.Fatalf("err = %v", err)
		}
		if _, _, err := CompleteJSON[map[string]any](context.Background(), p, Request{}, nil); !errors.Is(err, ErrDisabled) {
			t.Fatalf("CompleteJSON err = %v", err)
		}
		if _, err := WithRedaction(p).Complete(context.Background(), Request{}); !errors.Is(err, ErrDisabled) {
			t.Fatalf("redacted err = %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server hit %d times", hits.Load())
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network access is not allowed")
}

func TestNewErrors(t *testing.T) {
	cases := map[string]Config{
		"unknown provider":  {Provider: "nope"},
		"missing base url":  {Provider: ProviderOpenAICompatible, ModelFast: "m"},
		"missing model":     {Provider: ProviderOpenAICompatible, BaseURL: "http://x"},
		"bad base url":      {Provider: ProviderOpenAICompatible, BaseURL: "ftp://x", ModelFast: "m"},
		"bad structured":    {Provider: ProviderOpenAICompatible, BaseURL: "http://x", ModelFast: "m", StructuredOutput: "maybe"},
		"anthropic not reg": {Provider: ProviderAnthropic},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestTruncateMiddle(t *testing.T) {
	s := strings.Repeat("a", 500) + strings.Repeat("é", 500) + strings.Repeat("z", 500)
	got := TruncateMiddle(s, 300)
	if len(got) > 300 || !strings.Contains(got, "[... truncated ...]") ||
		!strings.HasPrefix(got, "aaa") || !strings.HasSuffix(got, "zzz") {
		t.Fatalf("bad truncation: len=%d %q", len(got), got)
	}
	for _, r := range got {
		if r == 0xFFFD {
			t.Fatal("split a UTF-8 sequence")
		}
	}
	if TruncateMiddle("short", 300) != "short" {
		t.Fatal("short input changed")
	}
}

func TestPrepareCapsInput(t *testing.T) {
	cfg := Config{MaxInputBytes: 2048}.WithDefaults()
	req := cfg.Prepare(Request{System: "sys", Messages: []Message{{Role: "user", Text: strings.Repeat("x", 100000)}}})
	if len(req.Messages[0].Text) > 2048 || req.MaxTokens != DefaultMaxTokens {
		t.Fatalf("len=%d max=%d", len(req.Messages[0].Text), req.MaxTokens)
	}
}

// ---- OpenAI-compatible adapter ----

type captured struct {
	mu     sync.Mutex
	bodies []map[string]any
	auth   []string
	paths  []string
}

func (c *captured) record(r *http.Request) {
	var b map[string]any
	_ = json.NewDecoder(r.Body).Decode(&b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, b)
	c.auth = append(c.auth, r.Header.Get("Authorization"))
	c.paths = append(c.paths, r.URL.Path)
}

func oaReply(content, finish string) string {
	b, _ := json.Marshal(map[string]any{
		"model": "m-1",
		"choices": []any{map[string]any{
			"message":       map[string]any{"role": "assistant", "content": content},
			"finish_reason": finish,
		}},
		"usage": map[string]any{"prompt_tokens": 7, "completion_tokens": 3},
	})
	return string(b)
}

func newOA(t *testing.T, h http.HandlerFunc, mut func(*Config)) Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := Config{Provider: ProviderOpenAICompatible, BaseURL: srv.URL + "/v1", ModelFast: "fast-m", ModelStrong: "strong-m"}
	if mut != nil {
		mut(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var pickSchema = json.RawMessage(`{"type":"object","properties":{"paths":{"type":"array","items":{"type":"string"}}},"required":["paths"],"additionalProperties":false}`)

func TestOpenAIRequestShape(t *testing.T) {
	var c captured
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		c.record(r)
		_, _ = w.Write([]byte(oaReply(`{"paths":["/a"]}`, "stop")))
	}, func(cfg *Config) { cfg.APIKey = "sekret" })
	resp, err := p.Complete(context.Background(), Request{
		Tier: TierStrong, System: "be brief", SchemaName: "pick", Schema: pickSchema,
		Messages: []Message{{Role: "user", Text: "go"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != `{"paths":["/a"]}` || resp.Model != "m-1" || resp.StopReason != "stop" || resp.InputTokens != 7 || resp.OutputTokens != 3 {
		t.Fatalf("resp = %+v", resp)
	}
	b := c.bodies[0]
	if c.paths[0] != "/v1/chat/completions" || c.auth[0] != "Bearer sekret" {
		t.Fatalf("path=%s auth=%s", c.paths[0], c.auth[0])
	}
	if b["model"] != "strong-m" || b["max_tokens"].(float64) != 2048 {
		t.Fatalf("body = %v", b)
	}
	if _, ok := b["temperature"]; ok {
		t.Fatal("temperature must not be sent")
	}
	msgs := b["messages"].([]any)
	if msgs[0].(map[string]any)["role"] != "system" || msgs[1].(map[string]any)["content"] != "go" {
		t.Fatalf("messages = %v", msgs)
	}
	rf := b["response_format"].(map[string]any)
	js := rf["json_schema"].(map[string]any)
	if rf["type"] != "json_schema" || js["name"] != "pick" || js["strict"] != true || js["schema"] == nil {
		t.Fatalf("response_format = %v", rf)
	}
}

func TestOpenAINoAuthHeaderWithoutKey(t *testing.T) {
	var c captured
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		c.record(r)
		_, _ = w.Write([]byte(oaReply("ok", "stop")))
	}, nil)
	if _, err := p.Complete(context.Background(), Request{Tier: TierFast, Messages: []Message{{Role: "user", Text: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if c.auth[0] != "" || c.bodies[0]["model"] != "fast-m" {
		t.Fatalf("auth=%q body=%v", c.auth[0], c.bodies[0])
	}
}

func TestOpenAIBaseURLWithoutVersion(t *testing.T) {
	var c captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.record(r)
		_, _ = w.Write([]byte(oaReply("ok", "stop")))
	}))
	defer srv.Close()
	p, err := New(Config{Provider: ProviderOpenAICompatible, BaseURL: srv.URL + "/", ModelFast: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), Request{}); err != nil {
		t.Fatal(err)
	}
	if c.paths[0] != "/v1/chat/completions" {
		t.Fatalf("path = %s", c.paths[0])
	}
}

func TestOpenAIStructuredModes(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		wantFormat bool
		wantPrompt bool
	}{{StructuredAuto, true, false}, {StructuredOn, true, false}, {StructuredOff, false, true}} {
		var c captured
		p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
			c.record(r)
			_, _ = w.Write([]byte(oaReply("{}", "stop")))
		}, func(cfg *Config) { cfg.StructuredOutput = tc.mode })
		if _, err := p.Complete(context.Background(), Request{Schema: pickSchema, System: "s"}); err != nil {
			t.Fatal(err)
		}
		_, hasFmt := c.bodies[0]["response_format"]
		sys := c.bodies[0]["messages"].([]any)[0].(map[string]any)["content"].(string)
		if hasFmt != tc.wantFormat || strings.Contains(sys, "JSON Schema") != tc.wantPrompt {
			t.Errorf("%s: format=%v prompt=%v (%s)", tc.mode, hasFmt, strings.Contains(sys, "JSON Schema"), sys)
		}
	}
}

func TestOpenAIAutoFallbackRemembered(t *testing.T) {
	var c captured
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		c.record(r)
		if _, ok := c.bodies[len(c.bodies)-1]["response_format"]; ok {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"Unsupported parameter: response_format"}}`))
			return
		}
		_, _ = w.Write([]byte(oaReply(`{"paths":[]}`, "stop")))
	}, nil)
	for i := 0; i < 2; i++ {
		resp, err := p.Complete(context.Background(), Request{Schema: pickSchema})
		if err != nil || resp.Text != `{"paths":[]}` {
			t.Fatalf("call %d: %v %+v", i, err, resp)
		}
	}
	// First call: with + without; second call: without only (remembered).
	if len(c.bodies) != 3 {
		t.Fatalf("requests = %d, want 3", len(c.bodies))
	}
	if _, ok := c.bodies[2]["response_format"]; ok {
		t.Fatal("second call should not send response_format")
	}
	if sys := c.bodies[1]["messages"].([]any)[0].(map[string]any)["content"].(string); !strings.Contains(sys, "JSON Schema") {
		t.Fatalf("fallback lacks schema in prompt: %s", sys)
	}
}

func TestOpenAIOnModeDoesNotFallBack(t *testing.T) {
	var n atomic.Int32
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"message":"bad response_format"}}`))
	}, func(cfg *Config) { cfg.StructuredOutput = StructuredOn })
	_, err := p.Complete(context.Background(), Request{Schema: pickSchema})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || n.Load() != 1 {
		t.Fatalf("err=%v n=%d", err, n.Load())
	}
}

func TestOpenAIOther400DoesNotFallBack(t *testing.T) {
	var n atomic.Int32
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"message":"model not found"}}`))
	}, nil)
	if _, err := p.Complete(context.Background(), Request{Schema: pickSchema}); err == nil || n.Load() != 1 {
		t.Fatalf("err=%v n=%d", err, n.Load())
	}
}

func TestOpenAIFinishReasonsAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		check  func(error) bool
	}{
		{"length", 200, oaReply(`{"pa`, "length"), func(e error) bool { return errors.Is(e, ErrTruncated) }},
		{"content filter", 200, oaReply("", "content_filter"), func(e error) bool { return errors.Is(e, ErrRefused) }},
		{"refusal field", 200, `{"choices":[{"message":{"content":null,"refusal":"no"},"finish_reason":"stop"}]}`, func(e error) bool { return errors.Is(e, ErrRefused) }},
		{"500", 500, `{"error":"boom"}`, func(e error) bool {
			var a *APIError
			return errors.As(e, &a) && a.StatusCode == 500 && a.Retryable() && strings.Contains(a.Message, "boom")
		}},
		{"429", 429, `{}`, func(e error) bool {
			var a *APIError
			return errors.As(e, &a) && a.Retryable()
		}},
		{"401 not retryable", 401, `{"error":{"message":"nope"}}`, func(e error) bool {
			var a *APIError
			return errors.As(e, &a) && !a.Retryable()
		}},
		{"malformed", 200, `{not json`, func(e error) bool { return e != nil }},
		{"no choices", 200, `{"choices":[]}`, func(e error) bool { return e != nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, nil)
			_, err := p.Complete(context.Background(), Request{})
			if !tc.check(err) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestOpenAITimeoutAndCancellation(t *testing.T) {
	block := make(chan struct{})
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}, func(cfg *Config) { cfg.Timeout = 50 * time.Millisecond })
	defer close(block)
	start := time.Now()
	if _, err := p.Complete(context.Background(), Request{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Complete(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("too slow")
	}
}

func TestOpenAIErrorsDoNotLeakKey(t *testing.T) {
	p := newOA(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"message":"bad"}}`))
	}, func(cfg *Config) { cfg.APIKey = "super-secret-key" })
	_, err := p.Complete(context.Background(), Request{})
	if err == nil || strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("err = %v", err)
	}
}

func TestWithRedactionRedactsEverythingSent(t *testing.T) {
	var c captured
	p := WithRedaction(newOA(t, func(w http.ResponseWriter, r *http.Request) {
		c.record(r)
		_, _ = w.Write([]byte(oaReply("ok", "stop")))
	}, nil))
	if p.Name() != ProviderOpenAICompatible {
		t.Fatal(p.Name())
	}
	_, err := p.Complete(context.Background(), Request{
		System:   "key AKIAABCDEFGHIJKLMNOP",
		Messages: []Message{{Role: "user", Text: "password=hunter2 at /etc/app.conf"}, {Role: "assistant", Text: "mail bob@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c.bodies[0])
	for _, leak := range []string{"AKIAABCDEFGHIJKLMNOP", "hunter2", "bob@example.com"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("leaked %q in %s", leak, raw)
		}
	}
	if !strings.Contains(string(raw), "/etc/app.conf") {
		t.Error("path was redacted")
	}
}
