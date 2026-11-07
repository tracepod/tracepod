package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tracepod/tracepod/ai/candidates"
)

func diagnoseArgs(t *testing.T, logName string, extra ...string) []string {
	t.Helper()
	return append([]string{
		"--inventory", filepath.Join("testdata", "diagnose", "inventory.json"),
		"--log", filepath.Join("testdata", "diagnose", logName),
	}, extra...)
}

func TestDiagnoseDeterministic(t *testing.T) {
	cases := []struct {
		log      string
		want     []string
		rerun    string
		nothing  bool
		wantNote string
	}{
		{log: "nginx.log", want: []string{"/etc/nginx/mime.types"}, rerun: "harden build ... --include /etc/nginx/mime.types --mkdir /var/cache/nginx"},
		{log: "python.log", want: []string{"/usr/local/lib/python3.12/site-packages/yaml"}},
		{log: "env.log", nothing: true},
		{log: "python-submodule.log", nothing: true, wantNote: "1 weaker matches were not ranked"},
	}
	for _, c := range cases {
		t.Run(c.log, func(t *testing.T) {
			code, out, errOut := runCmd(t, runDiagnoseWith, diagnoseArgs(t, c.log), nil, noNetwork(t), "")
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			if c.nothing {
				if !strings.Contains(out, diagnoseNothingFound) || strings.Contains(out, "--include") {
					t.Fatalf("out:\n%s", out)
				}
				if c.wantNote != "" && !strings.Contains(out, c.wantNote) {
					t.Fatalf("missing note %q in:\n%s", c.wantNote, out)
				}
				return
			}
			for _, p := range c.want {
				if !strings.Contains(out, p) || !strings.Contains(out, "[deterministic]") || !strings.Contains(out, "--include "+p) {
					t.Fatalf("want %s in:\n%s", p, out)
				}
			}
			if c.rerun != "" && !strings.Contains(out, "\n  "+c.rerun+"\n") {
				t.Fatalf("want re-run line %q in:\n%s", c.rerun, out)
			}
		})
	}
}

func TestDiagnoseStdinAndOutputDir(t *testing.T) {
	dir := t.TempDir()
	inv, _ := os.ReadFile(filepath.Join("testdata", "diagnose", "inventory.json"))
	os.WriteFile(filepath.Join(dir, "inventory.json"), inv, 0o644)
	logText, _ := os.ReadFile(filepath.Join("testdata", "diagnose", "nginx.log"))
	code, out, errOut := runCmd(t, runDiagnoseWith, []string{"--output", dir, "--log", "-", "--json"}, nil, noNetwork(t), string(logText))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var got diagnoseOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Suggestions) != 2 || got.Suggestions[0].Path != "/etc/nginx/mime.types" || got.Suggestions[0].Source != "deterministic" ||
		got.Suggestions[1].Path != "/var/cache/nginx" || got.Suggestions[1].Flag != "--mkdir" {
		t.Fatalf("got %+v", got)
	}
	if got.Rerun != "harden build ... --include /etc/nginx/mime.types --mkdir /var/cache/nginx" {
		t.Fatalf("rerun %q", got.Rerun)
	}
}

func TestDiagnoseInputErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no log", []string{"--output", t.TempDir()}, "--log"},
		{"no inventory", []string{"--output", t.TempDir(), "--log", filepath.Join("testdata", "diagnose", "nginx.log")}, "inventory.json not found"},
		{"bad provider", diagnoseArgs(t, "nginx.log", "--ai-provider", "bedrock"), "not built into harden"},
		{"missing key", diagnoseArgs(t, "nginx.log", "--ai-provider", "anthropic"), "requires TRACEPOD_AI_API_KEY or ANTHROPIC_API_KEY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := runCmd(t, runDiagnoseWith, c.args, nil, noNetwork(t), "")
			if code != 2 || !strings.Contains(errOut, c.want) {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
		})
	}
}

// No environment, or AI configured with --no-ai: zero network calls.
func TestDiagnoseNoNetwork(t *testing.T) {
	configured := map[string]string{"TRACEPOD_AI_PROVIDER": "openai-compatible", "TRACEPOD_AI_BASE_URL": "http://192.0.2.1/v1", "TRACEPOD_AI_MODEL": "m"}
	for _, c := range []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"no env", nil, nil},
		{"provider off", map[string]string{"TRACEPOD_AI_PROVIDER": "off"}, nil},
		{"--no-ai", configured, []string{"--no-ai"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, log := range []string{"nginx.log", "python-submodule.log", "env.log"} {
				code, _, errOut := runCmd(t, runDiagnoseWith, diagnoseArgs(t, log, c.args...), c.env, noNetwork(t), "")
				if code != 0 {
					t.Fatalf("%s: exit %d: %s", log, code, errOut)
				}
				code, _, errOut = runCmd(t, runExplainWith, append([]string{"--output", explainDir(t, true)}, c.args...), c.env, noNetwork(t), "")
				if code != 0 {
					t.Fatalf("explain: exit %d: %s", code, errOut)
				}
			}
		})
	}
}

func TestDiagnoseModel(t *testing.T) {
	const loader = "/usr/local/lib/python3.12/site-packages/yaml/loader.py"
	t.Run("valid pick", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": ["` + loader + `"]}`}}
		srv := fm.server(t)
		code, out, errOut := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "python-submodule.log"), fm.env(srv), nil, "")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		if !strings.Contains(out, "Suggested by model (fake-model-1):") || !strings.Contains(out, "--include "+loader) {
			t.Fatalf("out:\n%s", out)
		}
		if len(fm.requests) != 1 {
			t.Fatalf("%d requests", len(fm.requests))
		}
	})
	t.Run("invented path dropped", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": ["/usr/lib/python3/yaml/"]}`}}
		srv := fm.server(t)
		code, out, _ := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "python-submodule.log"), fm.env(srv), nil, "")
		if code != 0 || strings.Contains(out, "/usr/lib/python3/yaml/") || !strings.Contains(out, "model suggestions unavailable: the answer was rejected") {
			t.Fatalf("exit %d, out:\n%s", code, out)
		}
		if len(fm.requests) != 2 {
			t.Fatalf("want one retry, got %d requests", len(fm.requests))
		}
	})
	t.Run("paths under a picked directory are folded", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": ["` + loader + `"]}`}}
		srv := fm.server(t)
		// The yaml directory is a deterministic basename match; the model picks
		// a file inside it.
		logText := "ModuleNotFoundError: No module named 'yaml.loader'\nNo module named 'yaml'\n"
		args := []string{"--inventory", filepath.Join("testdata", "diagnose", "inventory.json"), "--log", "-"}
		_, out, _ := runCmd(t, runDiagnoseWith, args, fm.env(srv), nil, logText)
		if len(fm.requests) != 1 || strings.Contains(out, loader) || strings.Contains(out, "rejected") ||
			!strings.Contains(out, "--include /usr/local/lib/python3.12/site-packages/yaml\n") {
			t.Fatalf("%d requests, out:\n%s", len(fm.requests), out)
		}
	})
	t.Run("retry recovers", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": ["/nope"]}`, `{"paths": ["` + loader + `"]}`}}
		srv := fm.server(t)
		_, out, _ := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "python-submodule.log"), fm.env(srv), nil, "")
		if !strings.Contains(out, "--include "+loader) || strings.Contains(out, "/nope") {
			t.Fatalf("out:\n%s", out)
		}
	})
	t.Run("empty selection", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": []}`}}
		srv := fm.server(t)
		_, out, _ := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "python-submodule.log"), fm.env(srv), nil, "")
		if !strings.Contains(out, diagnoseNothingFound) {
			t.Fatalf("out:\n%s", out)
		}
	})
	t.Run("refusal keeps deterministic", func(t *testing.T) {
		fm := &fakeModel{answers: []string{""}, finish: "refusal"}
		srv := fm.server(t)
		code, out, _ := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "python-submodule.log"), fm.env(srv), nil, "")
		if code != 0 || !strings.Contains(out, diagnoseNothingFound) || !strings.Contains(out, "refused") {
			t.Fatalf("exit %d, out:\n%s", code, out)
		}
	})
	t.Run("deterministic only, no model call", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": []}`}}
		srv := fm.server(t)
		_, out, _ := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "nginx.log"), fm.env(srv), nil, "")
		if len(fm.requests) != 0 || !strings.Contains(out, "/etc/nginx/mime.types") {
			t.Fatalf("%d requests, out:\n%s", len(fm.requests), out)
		}
	})
	t.Run("prompt is redacted", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "app.log")
		secretLog := "error: cannot load yaml.loader: password=hunter2 from db at 10.1.2.3, token ghp_abcdefghijklmnopqrstuvwxyz0123\n" +
			"ModuleNotFoundError: No module named 'yaml.loader'\n"
		os.WriteFile(logPath, []byte(secretLog), 0o644)
		fm := &fakeModel{answers: []string{`{"paths": []}`}}
		srv := fm.server(t)
		args := []string{"--inventory", filepath.Join("testdata", "diagnose", "inventory.json"), "--log", logPath}
		runCmd(t, runDiagnoseWith, args, fm.env(srv), nil, "")
		sent := fm.sentText()
		if len(fm.requests) == 0 {
			t.Fatal("no request sent")
		}
		for _, s := range []string{"hunter2", "10.1.2.3", "ghp_abcdefghijklmnopqrstuvwxyz0123"} {
			if strings.Contains(sent, s) {
				t.Errorf("prompt contains %q", s)
			}
		}
	})
	t.Run("anthropic uses the compatible endpoint and key", func(t *testing.T) {
		fm := &fakeModel{answers: []string{`{"paths": []}`}}
		srv := fm.server(t)
		env := map[string]string{"TRACEPOD_AI_PROVIDER": "anthropic", "TRACEPOD_AI_BASE_URL": srv.URL + "/v1", "ANTHROPIC_API_KEY": "sk-ant-test"}
		_, _, errOut := runCmd(t, runDiagnoseWith, diagnoseArgs(t, "python-submodule.log"), env, nil, "")
		if len(fm.requests) != 1 {
			t.Fatalf("%d requests: %s", len(fm.requests), errOut)
		}
		if fm.auth[0] != "Bearer sk-ant-test" {
			t.Errorf("auth header %q", fm.auth[0])
		}
		if fm.requests[0]["model"] != anthropicDefaultModel {
			t.Errorf("model %v", fm.requests[0]["model"])
		}
		if _, ok := fm.requests[0]["response_format"]; ok {
			t.Error("response_format sent to the anthropic endpoint")
		}
	})
}

// Every printed path is a removed path from the inventory.
func TestDiagnoseOnlyRemovedPaths(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "diagnose", "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := candidates.LoadInventory(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	removed := map[string]bool{}
	for _, e := range entries {
		if !e.InHardened {
			removed[e.Path] = true
		}
	}
	for _, log := range []string{"nginx.log", "python.log", "python-submodule.log", "env.log"} {
		fm := &fakeModel{answers: []string{`{"paths": ["/usr/local/lib/python3.12/site-packages/yaml/loader.py"]}`}}
		srv := fm.server(t)
		_, out, _ := runCmd(t, runDiagnoseWith, diagnoseArgs(t, log, "--json"), fm.env(srv), nil, "")
		var got diagnoseOutput
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%s: %v", log, err)
		}
		for _, s := range got.Suggestions {
			if !removed[s.Path] {
				t.Errorf("%s: suggested %s, which is not a removed path", log, s.Path)
			}
		}
	}
}
