package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// sampleProfiles returns two ProfileSummary values for use in handler stubs.
func sampleProfiles() []ProfileSummary {
	now := time.Now().UTC()
	return []ProfileSummary{
		{Namespace: "ns1", Deployment: "dep-a", Status: "active", FileCount: 3, StartedAt: now},
		{Namespace: "ns2", Deployment: "dep-b", Status: "stopped", FileCount: 7, StartedAt: now},
	}
}

func serveProfiles(profiles []ProfileSummary) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(profiles)
	}))
}

func TestListProfiles_All(t *testing.T) {
	srv := serveProfiles(sampleProfiles())
	defer srv.Close()

	got, err := ListProfiles(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("want 2 profiles, got %d", len(got))
	}
}

func TestListProfiles_NamespaceFilter(t *testing.T) {
	srv := serveProfiles(sampleProfiles())
	defer srv.Close()

	got, err := ListProfiles(context.Background(), srv.URL, "ns1")
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 profile after filter, got %d", len(got))
	}
	if got[0].Namespace != "ns1" {
		t.Errorf("want ns1, got %q", got[0].Namespace)
	}
}

func TestListProfiles_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := ListProfiles(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestGetProfile_OK(t *testing.T) {
	payload := `{"schema_version":"1"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	got, err := GetProfile(context.Background(), srv.URL, "ns1", "dep1")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if string(got) != payload {
		t.Errorf("want %q, got %q", payload, string(got))
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := GetProfile(context.Background(), srv.URL, "ns1", "missing")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestStopProfile_OK(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := StopProfile(context.Background(), srv.URL, "ns1", "dep1"); err != nil {
		t.Fatalf("StopProfile: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: want POST, got %q", gotMethod)
	}
	if gotPath != "/api/v1/profiles/ns1/dep1/stop" {
		t.Errorf("path: want /api/v1/profiles/ns1/dep1/stop, got %q", gotPath)
	}
}

func TestStopProfile_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	err := StopProfile(context.Background(), srv.URL, "ns1", "dep1")
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}
