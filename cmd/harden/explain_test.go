package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// noNetwork is an http.Client whose transport fails the test on any use.
func noNetwork(t *testing.T) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("unexpected network call to %s", r.URL)
		return nil, errors.New("network disabled in test")
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// fakeModel is an OpenAI-compatible endpoint that answers with the given
// assistant messages in turn (the last one repeats) and records requests.
type fakeModel struct {
	mu       sync.Mutex
	answers  []string
	finish   string
	requests []map[string]any
	auth     []string
}

func (f *fakeModel) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("bad request body: %v", err)
		}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		i := min(len(f.requests)-1, len(f.answers)-1)
		answer := f.answers[i]
		f.mu.Unlock()
		finish := f.finish
		if finish == "" {
			finish = "stop"
		}
		msg := map[string]any{"content": answer}
		if finish == "refusal" {
			msg = map[string]any{"content": nil, "refusal": "I can't help with that."}
			finish = "stop"
		}
		json.NewEncoder(w).Encode(map[string]any{
			"model":   "fake-model-1",
			"choices": []any{map[string]any{"message": msg, "finish_reason": finish}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeModel) env(srv *httptest.Server) map[string]string {
	return map[string]string{
		"TRACEPOD_AI_PROVIDER": "openai-compatible",
		"TRACEPOD_AI_BASE_URL": srv.URL + "/v1",
		"TRACEPOD_AI_MODEL":    "fake-model-1",
	}
}

func (f *fakeModel) sentText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.requests)
	return string(b)
}

func runCmd(t *testing.T, run func([]string, cmdEnv) int, args []string, env map[string]string, client *http.Client, stdin string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, cmdEnv{getenv: envFrom(env), client: client, stdin: strings.NewReader(stdin), stdout: &stdout, stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

// explainDir copies the explain fixture into a temp output directory, with or
// without the inventory.
func explainDir(t *testing.T, withInventory bool) string {
	t.Helper()
	dir := t.TempDir()
	files := []string{"removal-manifest.json"}
	if withInventory {
		files = append(files, "inventory.json")
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join("testdata", "explain", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "explain", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden %s (run go test -update): %v", p, err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestExplainGolden(t *testing.T) {
	manifest := filepath.Join("testdata", "explain", "manifest.json")
	cases := []struct {
		golden string
		inv    bool
		args   []string
	}{
		{"explain.golden", true, []string{"--manifest", manifest}},
		{"explain.json.golden", true, []string{"--manifest", manifest, "--json"}},
		{"explain-noinventory.golden", false, nil},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			dir := explainDir(t, c.inv)
			code, out, errOut := runCmd(t, runExplainWith, append([]string{"--output", dir}, c.args...), nil, noNetwork(t), "")
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			checkGolden(t, c.golden, out)
		})
	}
}

func TestExplainMissingRemovalManifest(t *testing.T) {
	code, _, errOut := runCmd(t, runExplainWith, []string{"--output", t.TempDir()}, nil, noNetwork(t), "")
	if code != 2 || !strings.Contains(errOut, "removal-manifest.json not found") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

// With AI configured but --no-ai, nothing is sent.
func TestExplainNoAIFlag(t *testing.T) {
	env := map[string]string{"TRACEPOD_AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-test"}
	code, out, errOut := runCmd(t, runExplainWith, []string{"--output", explainDir(t, true), "--no-ai"}, env, noNetwork(t), "")
	if code != 0 || strings.Contains(out, "Summary (model") {
		t.Fatalf("exit %d, out %q, err %q", code, out, errOut)
	}
}

func TestExplainProse(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fm := &fakeModel{answers: []string{"The build removed 18 files, including the busybox shell /bin/sh and the package manager /sbin/apk, which shrinks what an attacker can use. Check that `curl` is not needed."}}
		srv := fm.server(t)
		code, out, errOut := runCmd(t, runExplainWith, []string{"--output", explainDir(t, true), "--json"}, fm.env(srv), nil, "")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		var got explainOutput
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if got.Prose == "" || got.Model != "fake-model-1" || got.Note != "" {
			t.Fatalf("got %+v", got)
		}
		// Only the deterministic block is sent.
		sent := fm.sentText()
		if !strings.Contains(sent, "Largest removed packages") || strings.Contains(sent, "nginx.conf") {
			t.Errorf("unexpected prompt: %s", sent)
		}
	})
	t.Run("invented path dropped", func(t *testing.T) {
		fm := &fakeModel{answers: []string{"The build removed /usr/bin/python3, which is safe."}}
		srv := fm.server(t)
		code, out, _ := runCmd(t, runExplainWith, []string{"--output", explainDir(t, true)}, fm.env(srv), nil, "")
		if code != 0 || strings.Contains(out, "Summary (model") || !strings.Contains(out, `names "/usr/bin/python3"`) {
			t.Fatalf("exit %d, out:\n%s", code, out)
		}
	})
	t.Run("invented package dropped", func(t *testing.T) {
		fm := &fakeModel{answers: []string{"The build removed `openssl`."}}
		srv := fm.server(t)
		_, out, _ := runCmd(t, runExplainWith, []string{"--output", explainDir(t, true)}, fm.env(srv), nil, "")
		if strings.Contains(out, "Summary (model") || !strings.Contains(out, "Note: model summary unavailable") {
			t.Fatalf("out:\n%s", out)
		}
	})
	t.Run("too long dropped", func(t *testing.T) {
		fm := &fakeModel{answers: []string{strings.Repeat("word ", 200)}}
		srv := fm.server(t)
		_, out, _ := runCmd(t, runExplainWith, []string{"--output", explainDir(t, true)}, fm.env(srv), nil, "")
		if strings.Contains(out, "Summary (model") || !strings.Contains(out, "200 words") {
			t.Fatalf("out:\n%s", out)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		fm := &fakeModel{answers: []string{""}, finish: "refusal"}
		srv := fm.server(t)
		code, out, _ := runCmd(t, runExplainWith, []string{"--output", explainDir(t, true)}, fm.env(srv), nil, "")
		if code != 0 || !strings.Contains(out, "Build summary") || !strings.Contains(out, "refused") {
			t.Fatalf("exit %d, out:\n%s", code, out)
		}
	})
}

func TestCheckProse(t *testing.T) {
	input := "Removed: /bin/sh, /usr/share/doc/nginx/README\n  busybox 1.36.1-r29  4 paths"
	for _, c := range []struct {
		prose string
		ok    bool
	}{
		{"Removed /bin/sh and docs such as /usr/share/doc/nginx/README.", true},
		{"Removed the busybox shell, and/or other tools; 4 paths.", true},
		{`It removed "busybox".`, true},
		{"It removed /bin/bash.", false},
		{"It removed `bash`.", false},
		{"It removed /usr/share/doc/.", true},
	} {
		err := checkProse(c.prose, input)
		if (err == nil) != c.ok {
			t.Errorf("checkProse(%q) = %v, want ok=%v", c.prose, err, c.ok)
		}
	}
}

func TestPathCategory(t *testing.T) {
	for p, want := range map[string]string{
		"/bin/sh":                    catShells,
		"/usr/bin/bash":              catShells,
		"/usr/bin/ssh":               catNetTools,
		"/usr/bin/curl":              catNetTools,
		"/usr/bin/apt-get":           catPkgMgrs,
		"/usr/local/bin/pip3.12":     catPkgMgrs,
		"/var/lib/dpkg/status":       catPkgMgrs,
		"/usr/share/man/man1/ls.1":   catDocs,
		"/usr/lib/go/src/os/test/x":  catTests,
		"/usr/share/locale/de/x.mo":  catLocale,
		"/usr/lib/libc.so":           "",
		"/opt/app/flash":             "",
		"/usr/share/zoneinfo/Europe": "",
	} {
		if got := pathCategory(p); got != want {
			t.Errorf("pathCategory(%q) = %q, want %q", p, got, want)
		}
	}
}
