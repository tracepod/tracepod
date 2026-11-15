package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/tracepod/tracepod/manifest"
)

// PostProfile marshals m and HTTP POSTs it to the controller's ingest endpoint:
//
//	{controllerURL}/internal/profiles/{namespace}/{deployment}?pod={podName}&node={nodeName}
//
// When tokenFile is non-empty, the file is read on every call (the kubelet
// rotates projected ServiceAccount tokens in place) and its trimmed contents
// are sent as "Authorization: Bearer <token>". An unreadable or empty token
// file is an error: the request is not sent unauthenticated. An empty
// tokenFile sends no Authorization header.
//
// The provided context controls the request timeout.
func PostProfile(ctx context.Context, controllerURL, tokenFile, namespace, deployment, podName, nodeName string, m manifest.Manifest) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	url := fmt.Sprintf("%s/internal/profiles/%s/%s?pod=%s&node=%s",
		controllerURL, namespace, deployment, podName, nodeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tokenFile != "" {
		tok, err := ReadToken(tokenFile)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("controller returned %d", resp.StatusCode)
	}
	return nil
}

// ReadToken reads a bearer token from path and trims surrounding whitespace.
// It fails when the file cannot be read or holds no token. The token itself
// never appears in the returned error.
func ReadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read controller token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("read controller token file: " + path + " is empty")
	}
	return tok, nil
}
