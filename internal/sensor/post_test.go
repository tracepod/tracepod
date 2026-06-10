package sensor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	err := sensor.PostProfile(context.Background(), srv.URL, "ns1", "dep1", "pod1", "node1", emptyManifest())
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

	err := sensor.PostProfile(context.Background(), srv.URL, "ns", "dep", "pod", "node", emptyManifest())
	if err == nil {
		t.Fatal("expected error for non-201 response, got nil")
	}
}

func TestPostProfile_NetworkError(t *testing.T) {
	err := sensor.PostProfile(context.Background(), "http://127.0.0.1:1", "ns", "dep", "pod", "node", emptyManifest())
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}
