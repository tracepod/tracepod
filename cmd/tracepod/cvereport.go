package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// runCVEReport implements `tracepod cve-report <workload|profile-id>`. It is a
// pure rendering client of the controller's Lite-served reachability API: it
// fetches a report the controller produced and renders it. No classification,
// matching, scoring, or gating happens here.
func runCVEReport(args []string, kubeconfig, ctrlNS string) {
	fs := flag.NewFlagSet("cve-report", flag.ExitOnError)
	output := fs.String("output", "table", "output format: table | json")
	findings := fs.String("findings", "", "upload a Trivy/Grype findings JSON file instead of triggering a server-side scan")
	severity := fs.String("severity", "", "minimum severity to show in the table: critical|high|medium|low|negligible|all (default high)")
	namespace := fs.String("namespace", "", "namespace of the workload (disambiguates a workload name; ignored for a numeric profile-id)")
	controllerURL := fs.String("controller-url", "", "controller base URL (e.g. http://localhost:8080); bypasses the in-cluster port-forward")
	verbose := fs.Bool("verbose", false, "show the coverage-score breakdown and attribution evidence")
	fs.Parse(args) //nolint:errcheck

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: tracepod cve-report <workload|profile-id> [--findings <file>] [--severity <level>] [--output table|json] [--verbose]\n")
		os.Exit(1)
	}
	target := rest[0]

	sevThreshold, err := validateSeverity(*severity)
	if err != nil {
		fatal("%v", err)
	}
	if *output != "table" && *output != "json" {
		fatal("invalid --output %q (want table or json)", *output)
	}

	baseURL := strings.TrimRight(*controllerURL, "/")
	if baseURL == "" {
		var cleanup func()
		var err error
		baseURL, cleanup, err = connect(kubeconfig, ctrlNS)
		if err != nil {
			fatal("connect to controller: %v", err)
		}
		defer cleanup()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	profileID, err := resolveProfileID(ctx, baseURL, target, *namespace)
	if err != nil {
		fatal("%v", err)
	}

	var raw []byte
	if *findings != "" {
		raw, err = importFindings(ctx, baseURL, profileID, *findings)
	} else {
		raw, err = createAndAwaitReport(ctx, baseURL, profileID)
	}
	if err != nil {
		fatal("%v", err)
	}

	// R5: --output json is byte-faithful to the controller payload — no reshaping.
	if *output == "json" {
		_, _ = os.Stdout.Write(raw)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			fmt.Fprintln(os.Stdout)
		}
		return
	}

	rep, err := ParseReport(raw)
	if err != nil {
		// R4: a schema-invalid response is distinct from a connection failure.
		fatal("%v", err)
	}
	RenderHuman(os.Stdout, rep, renderOptions{severity: sevThreshold, verbose: *verbose})
}

// resolveProfileID maps the CLI target to a controller profile id. A numeric
// target is taken verbatim; a workload name is resolved to the most recent
// profiling session for that deployment (optionally scoped by namespace).
func resolveProfileID(ctx context.Context, baseURL, target, namespace string) (string, error) {
	if _, err := strconv.ParseInt(target, 10, 64); err == nil {
		return target, nil
	}
	profiles, err := listProfilesRaw(ctx, baseURL)
	if err != nil {
		return "", fmt.Errorf("resolve workload %q: %w", target, err)
	}
	var match *profileRef
	for i := range profiles {
		p := profiles[i]
		if p.Deployment != target {
			continue
		}
		if namespace != "" && p.Namespace != namespace {
			continue
		}
		if match == nil || p.StartedAt > match.StartedAt {
			match = &profiles[i]
		}
	}
	if match == nil {
		scope := target
		if namespace != "" {
			scope = namespace + "/" + target
		}
		return "", fmt.Errorf("no profiling session found for workload %q — run `tracepod profile list` to see available workloads", scope)
	}
	return match.ID, nil
}

// profileRef is the minimal slice of the profiles list the resolver needs.
type profileRef struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
	StartedAt  string `json:"started_at"`
}

func listProfilesRaw(ctx context.Context, baseURL string) ([]profileRef, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/profiles", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp.StatusCode, body)
	}
	// The current controller wraps the list in a {"profiles":[…]} envelope; older
	// shapes returned a bare array. Accept both so the resolver is robust to the
	// API-shape drift flagged during WP0.
	var env struct {
		Profiles []profileRef `json:"profiles"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Profiles != nil {
		return env.Profiles, nil
	}
	var profiles []profileRef
	if err := json.Unmarshal(body, &profiles); err != nil {
		return nil, fmt.Errorf("decode profiles list: %w", err)
	}
	return profiles, nil
}

// buildImportRequest constructs the POST for the findings-upload path
// (R1 --findings). Factored out so request construction is unit-testable without
// a controller.
func buildImportRequest(ctx context.Context, baseURL, profileID string, body []byte) (*http.Request, error) {
	u := fmt.Sprintf("%s/api/v1/reachability/reports/import?profile_id=%s",
		baseURL, url.QueryEscape(profileID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// importFindings uploads a Trivy/Grype findings file; the controller runs the
// reachability analysis synchronously and returns the rendered report inline.
func importFindings(ctx context.Context, baseURL, profileID, path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read findings file %q: %w", path, err)
	}
	req, err := buildImportRequest(ctx, baseURL, profileID, body)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp.StatusCode, respBody)
	}
	return respBody, nil
}

// buildCreateRequest constructs the POST that triggers a server-side scan.
func buildCreateRequest(ctx context.Context, baseURL, profileID string) (*http.Request, error) {
	payload, _ := json.Marshal(map[string]string{"profile_id": profileID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/v1/reachability/reports", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// createAndAwaitReport triggers a server-side scan and polls until the async run
// completes, returning the final report payload.
func createAndAwaitReport(ctx context.Context, baseURL, profileID string) ([]byte, error) {
	req, err := buildCreateRequest(ctx, baseURL, profileID)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return nil, serverError(resp.StatusCode, body)
	}
	var acc struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &acc); err != nil || acc.ID == "" {
		return nil, fmt.Errorf("controller did not return a run id for the scan")
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		raw, done, err := pollReport(ctx, baseURL, acc.ID)
		if err != nil {
			return nil, err
		}
		if done {
			return raw, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for reachability report (run %s)", acc.ID)
		case <-ticker.C:
		}
	}
}

// pollReport fetches a run; done is true once the full report is available. A
// failed run surfaces the controller's error message verbatim (R4).
func pollReport(ctx context.Context, baseURL, runID string) (raw []byte, done bool, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/api/v1/reachability/reports/"+url.PathEscape(runID), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, false, serverError(resp.StatusCode, body)
	}
	// A completed run returns the full report; otherwise a status envelope.
	var env struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Schema string `json:"schema"`
	}
	_ = json.Unmarshal(body, &env)
	if env.Schema != "" {
		return body, true, nil
	}
	if env.Status == "failed" {
		return nil, false, fmt.Errorf("reachability scan failed: %s", env.Error)
	}
	return nil, false, nil // still running
}

// serverError renders a controller error response via the CLI's error
// conventions, preserving the server's message intact (R4).
func serverError(status int, body []byte) error {
	var env struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != "" {
		return fmt.Errorf("controller error (HTTP %d): %s", status, env.Error)
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = "(no response body)"
	}
	return fmt.Errorf("controller returned HTTP %d: %s", status, msg)
}
