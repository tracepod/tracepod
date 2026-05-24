package hardener

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// TestIsECRHost verifies the hostname pattern that gates ECR credential helper
// invocation. A false negative silently falls back to anonymous auth; a false
// positive contacts the AWS metadata endpoint on non-cloud machines and hangs.
func TestIsECRHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"123456789.dkr.ecr.eu-west-1.amazonaws.com", true},
		{"123456789.dkr.ecr.us-east-1.amazonaws.com", true},
		{"public.ecr.aws", false},           // public ECR has no .dkr.ecr. component
		{"index.docker.io", false},
		{"ghcr.io", false},
		{"myregistry.azurecr.io", false},
		{"localhost:5001", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isECRHost(tc.host); got != tc.want {
			t.Errorf("isECRHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestIsACRHost verifies the hostname pattern that gates ACR credential helper
// invocation. A false positive contacts Azure IMDS (169.254.169.254) on
// non-Azure machines and hangs indefinitely.
func TestIsACRHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"myregistry.azurecr.io", true},
		{"corp.azurecr.io", true},
		{"index.docker.io", false},
		{"123456789.dkr.ecr.eu-west-1.amazonaws.com", false},
		{"ghcr.io", false},
		{"localhost:5001", false},
		{"azurecr.io.evil.com", false}, // suffix check, not substring
		{"", false},
	}
	for _, tc := range cases {
		if got := isACRHost(tc.host); got != tc.want {
			t.Errorf("isACRHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestDetectAuthSource verifies that the correct AuthSource is reported for
// each registry type. This exercises the routing logic from the caller side
// (same path the CLI uses to print the "Auth:" output line).
func TestDetectAuthSource(t *testing.T) {
	// Point DOCKER_CONFIG at an empty temp dir so this test is hermetic —
	// it must not depend on the presence or absence of docker credentials
	// on the test machine or CI runner.
	t.Setenv("DOCKER_CONFIG", t.TempDir())

	cases := []struct {
		imageRef string
		want     AuthSource
	}{
		// ECR references should always report AuthECR regardless of credentials.
		{"123456789.dkr.ecr.eu-west-1.amazonaws.com/myapp:latest", AuthECR},
		// ACR references should always report AuthACR.
		{"myregistry.azurecr.io/myapp:latest", AuthACR},
		// Docker Hub public image with no local docker config → anonymous.
		{"nginx:1.25-alpine", AuthAnonymous},
		// Explicit keychain overrides all.
		// (tested separately via isExplicit=true path)
	}
	kc := NewKeychain()
	for _, tc := range cases {
		got := DetectAuthSource(tc.imageRef, kc, false)
		if got != tc.want {
			t.Errorf("DetectAuthSource(%q) = %q, want %q", tc.imageRef, got, tc.want)
		}
	}

	// isExplicit=true always returns AuthExplicit regardless of ref or keychain.
	if got := DetectAuthSource("nginx:latest", kc, true); got != AuthExplicit {
		t.Errorf("DetectAuthSource with isExplicit=true: got %q, want %q", got, AuthExplicit)
	}

	// nil keychain → anonymous.
	if got := DetectAuthSource("nginx:latest", nil, false); got != AuthAnonymous {
		t.Errorf("DetectAuthSource with nil keychain: got %q, want %q", got, AuthAnonymous)
	}
}

// TestRoutingKeychain_DoesNotInvokeCloudHelpersForDockerHub verifies that the
// routing keychain resolves Docker Hub without invoking ECR or ACR helpers.
// If either cloud helper were invoked here it would contact a metadata endpoint
// and hang on non-cloud machines.
func TestRoutingKeychain_DoesNotInvokeCloudHelpersForDockerHub(t *testing.T) {
	ref, err := name.NewRepository("index.docker.io/library/nginx")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	kc := NewKeychain()
	auth, err := kc.Resolve(ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Must return a non-nil authenticator synchronously (no network call for Docker Hub).
	if auth == nil {
		t.Fatal("got nil authenticator for Docker Hub")
	}
	// Anonymous auth is expected when no docker config is present.
	_ = auth
}

// TestRoutingKeychain_ExplicitCredentials verifies that explicit credentials
// take priority over the routing keychain for any registry.
func TestRoutingKeychain_ExplicitCredentials(t *testing.T) {
	ref, err := name.NewRepository("index.docker.io/library/nginx")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	kc := NewExplicitKeychain("user", "s3cr3t")
	auth, err := kc.Resolve(ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatalf("Authorization: %v", err)
	}
	if cfg.Username != "user" {
		t.Errorf("expected username %q, got %q", "user", cfg.Username)
	}
}

// TestStaticKeychain_ReturnsAuthForAnyResource verifies that staticKeychain
// returns the same authenticator regardless of what resource is passed.
func TestStaticKeychain_ReturnsAuthForAnyResource(t *testing.T) {
	static := &staticKeychain{
		auth: authn.FromConfig(authn.AuthConfig{Username: "u", Password: "p"}),
	}
	refs := []string{
		"index.docker.io/library/nginx",
		"ghcr.io/myorg/myapp",
	}
	for _, r := range refs {
		repo, err := name.NewRepository(r)
		if err != nil {
			t.Fatalf("parse %q: %v", r, err)
		}
		auth, err := static.Resolve(repo)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", r, err)
		}
		cfg, err := auth.Authorization()
		if err != nil {
			t.Fatalf("Authorization(%q): %v", r, err)
		}
		if cfg.Username != "u" {
			t.Errorf("Resolve(%q): expected username %q, got %q", r, "u", cfg.Username)
		}
	}
}

func TestNewKeychain_ResolvesPublicImage(t *testing.T) {
	ref, err := name.NewRepository("index.docker.io/library/nginx")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	kc := NewKeychain()
	auth, err := kc.Resolve(ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Public images resolve to Anonymous — that is correct and expected.
	if auth == nil {
		t.Fatal("got nil authenticator")
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatalf("Authorization: %v", err)
	}
	// Anonymous auth has empty username — just verify no error path.
	_ = cfg
}

func TestNewExplicitKeychain_OverridesDefault(t *testing.T) {
	kc := NewExplicitKeychain("user", "pass")
	ref, err := name.NewRepository("index.docker.io/library/nginx")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	auth, err := kc.Resolve(ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatalf("Authorization: %v", err)
	}
	// staticKeychain always returns the explicit credentials regardless of registry.
	if cfg.Username != "user" {
		t.Errorf("expected username %q, got %q", "user", cfg.Username)
	}
}
