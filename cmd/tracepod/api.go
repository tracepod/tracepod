package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ProfileSummary mirrors the profileListItem JSON returned by GET /api/v1/profiles.
type ProfileSummary struct {
	Namespace  string     `json:"namespace"`
	Deployment string     `json:"deployment"`
	Status     string     `json:"status"`
	FileCount  int        `json:"file_count"`
	StartedAt  time.Time  `json:"started_at"`
	StoppedAt  *time.Time `json:"stopped_at,omitempty"`
}

// ListProfiles fetches GET /api/v1/profiles and returns all sessions.
// If namespace is non-empty, only sessions in that namespace are returned.
func ListProfiles(ctx context.Context, baseURL, namespace string) ([]ProfileSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/profiles", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /api/v1/profiles: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v1/profiles: server returned %d", resp.StatusCode)
	}
	var all []ProfileSummary
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		return nil, fmt.Errorf("decode profiles: %w", err)
	}
	if namespace == "" {
		return all, nil
	}
	var filtered []ProfileSummary
	for _, s := range all {
		if s.Namespace == namespace {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

// GetProfile fetches GET /api/v1/profiles/{ns}/{dep} and returns the raw JSON bytes.
func GetProfile(ctx context.Context, baseURL, namespace, deployment string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/profiles/%s/%s", baseURL, namespace, deployment)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no profile found for %s/%s", namespace, deployment)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET profile: server returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// StopProfile POSTs to /api/v1/profiles/{ns}/{dep}/stop.
func StopProfile(ctx context.Context, baseURL, namespace, deployment string) error {
	url := fmt.Sprintf("%s/api/v1/profiles/%s/%s/stop", baseURL, namespace, deployment)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stop profile: server returned %d", resp.StatusCode)
	}
	return nil
}
