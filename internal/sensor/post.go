package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tracepod/tracepod/manifest"
)

// PostProfile marshals m and HTTP POSTs it to the controller's ingest endpoint:
//
//	{controllerURL}/internal/profiles/{namespace}/{deployment}?pod={podName}&node={nodeName}
//
// The provided context controls the request timeout.
func PostProfile(ctx context.Context, controllerURL, namespace, deployment, podName, nodeName string, m manifest.Manifest) error {
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
