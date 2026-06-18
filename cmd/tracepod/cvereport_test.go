package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

// TestBuildImportRequest checks the --findings request construction (R1): a POST
// to the import endpoint with the profile_id query and the file bytes as the body.
func TestBuildImportRequest(t *testing.T) {
	body := []byte(`{"Results":[{"Vulnerabilities":[]}]}`)
	req, err := buildImportRequest(context.Background(), "http://ctrl:8080", "42", body)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %s, want POST", req.Method)
	}
	if got := req.URL.Path; got != "/api/v1/reachability/reports/import" {
		t.Errorf("path = %s", got)
	}
	if got := req.URL.Query().Get("profile_id"); got != "42" {
		t.Errorf("profile_id query = %q, want 42", got)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	gotBody, _ := io.ReadAll(req.Body)
	if string(gotBody) != string(body) {
		t.Errorf("body = %q, want %q (findings file uploaded verbatim)", gotBody, body)
	}
}

// TestBuildCreateRequest checks the server-side-scan trigger carries the profile id.
func TestBuildCreateRequest(t *testing.T) {
	req, err := buildCreateRequest(context.Background(), "http://ctrl:8080", "7")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL.Path != "/api/v1/reachability/reports" {
		t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
	}
	gotBody, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(gotBody), `"profile_id":"7"`) {
		t.Errorf("body = %q, want profile_id 7", gotBody)
	}
}

// TestResolveProfileID_Numeric: a numeric target is used verbatim (no network).
func TestResolveProfileID_Numeric(t *testing.T) {
	id, err := resolveProfileID(context.Background(), "http://unused", "99", "")
	if err != nil {
		t.Fatal(err)
	}
	if id != "99" {
		t.Errorf("id = %q, want 99", id)
	}
}

// TestServerError_PreservesMessage asserts R4: the controller's error message is
// rendered intact. Driven by the committed digest-mismatch error fixture.
func TestServerError_PreservesMessage(t *testing.T) {
	body := readFixture(t, "error-digest-mismatch.json")
	err := serverError(409, body)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "image digest or platform mismatch") {
		t.Errorf("server message not preserved; got: %v", err)
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("status code not surfaced; got: %v", err)
	}
}

// TestServerError_NonJSONBody falls back to the raw body when it is not the
// standard {"error":...} envelope.
func TestServerError_NonJSONBody(t *testing.T) {
	err := serverError(502, []byte("upstream connect error"))
	if !strings.Contains(err.Error(), "upstream connect error") || !strings.Contains(err.Error(), "502") {
		t.Errorf("unexpected: %v", err)
	}
}
