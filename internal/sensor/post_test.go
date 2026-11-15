package sensor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/sensor"
	"github.com/tracepod/tracepod/manifest"
)

func emptyManifest() manifest.Manifest {
	return manifest.Manifest{
		SchemaVersion:   manifest.SchemaVersion,
		ContainerID:     "ctr1",
		ImageRef:        "nginx:latest",
		ProfileStart:    time.Now().UTC(),
		ProfileEnd:      time.Now().UTC(),
		ContainerStarts: []manifest.StartEvent{},
		Files:           map[string]manifest.FileEntry{},
	}
}

func TestPostProfile_Success(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	err := sensor.PostProfile(context.Background(), srv.URL, "", "ns1", "dep1", "pod1", "node1", emptyManifest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/internal/profiles/ns1/dep1" {
		t.Errorf("path: want /internal/profiles/ns1/dep1, got %q", gotPath)
	}
	if !strings.Contains(gotQuery, "pod=pod1") {
		t.Errorf("query %q missing pod=pod1", gotQuery)
	}
	if !strings.Contains(gotQuery, "node=node1") {
		t.Errorf("query %q missing node=node1", gotQuery)
	}
}

func TestPostProfile_Non201Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := sensor.PostProfile(context.Background(), srv.URL, "", "ns", "dep", "pod", "node", emptyManifest())
	if err == nil {
		t.Fatal("expected error for non-201 response, got nil")
	}
}

func TestPostProfile_NetworkError(t *testing.T) {
	err := sensor.PostProfile(context.Background(), "http://127.0.0.1:1", "", "ns", "dep", "pod", "node", emptyManifest())
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestPostProfile_NoTokenFileSendsNoAuthorization(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Values("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	if err := sensor.PostProfile(context.Background(), srv.URL, "", "ns", "dep", "pod", "node", emptyManifest()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Authorization sent without a token file: %q", got)
	}
}

func TestPostProfile_TokenFileSendsBearerAndIsReread(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sensor.PostProfile(context.Background(), srv.URL, tokenFile, "ns", "dep", "pod", "node", emptyManifest()); err != nil {
		t.Fatalf("first POST: %v", err)
	}

	// The kubelet rotates projected tokens by replacing the file; the next
	// request must carry the new token, not a cached one.
	if err := os.WriteFile(tokenFile, []byte("second-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sensor.PostProfile(context.Background(), srv.URL, tokenFile, "ns", "dep", "pod", "node", emptyManifest()); err != nil {
		t.Fatalf("second POST: %v", err)
	}

	want := []string{"Bearer first-token", "Bearer second-token"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Authorization headers: want %q, got %q", want, got)
	}
}

func TestPostProfile_UnreadableOrEmptyTokenFileFailsWithoutSending(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(dir, "missing"), empty} {
		if err := sensor.PostProfile(context.Background(), srv.URL, f, "ns", "dep", "pod", "node", emptyManifest()); err == nil {
			t.Errorf("%s: expected an error", f)
		}
	}
	if calls != 0 {
		t.Errorf("request sent %d times without a usable token", calls)
	}
}
