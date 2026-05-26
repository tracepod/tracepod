// Package hardener pulls an OCI image, extracts the files listed in a sensor
// manifest, resolves ELF shared-library dependencies, and assembles a new
// FROM-scratch OCI image.
package hardener

import (
	"strings"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// AuthSource names the keychain entry that resolved credentials for a pull.
// Reported on the CLI "Auth:" line so operators know which cred path fired.
type AuthSource string

const (
	AuthDockerConfig AuthSource = "docker-config"
	AuthECR          AuthSource = "ecr-credential-helper"
	AuthACR          AuthSource = "acr-credential-helper"
	AuthExplicit     AuthSource = "explicit"
	AuthAnonymous    AuthSource = "anonymous"
)

// NewKeychain returns a keychain that routes credentials based on the target
// registry hostname:
//
//   - *.dkr.ecr.*.amazonaws.com  → ECR credential helper (AWS SDK chain)
//   - *.azurecr.io               → ACR credential helper (env vars / workload identity)
//   - everything else            → authn.DefaultKeychain (~/.docker/config.json)
//
// Cloud-provider helpers are only invoked for their respective registry
// domains. This prevents Azure IMDS / AWS metadata endpoint calls on
// non-cloud machines, which would otherwise hang indefinitely.
//
// When --username and --password are both provided, call NewExplicitKeychain
// instead, which prepends a static authenticator at highest priority.
func NewKeychain() authn.Keychain {
	return &routingKeychain{}
}

// routingKeychain dispatches to the correct credential helper based on
// the target registry hostname.
type routingKeychain struct{}

func (r *routingKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	host := res.RegistryStr()
	switch {
	case isECRHost(host):
		return authn.NewKeychainFromHelper(ecr.NewECRHelper()).Resolve(res)
	case isACRHost(host):
		return authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()).Resolve(res)
	default:
		return authn.DefaultKeychain.Resolve(res)
	}
}

func isECRHost(host string) bool {
	// *.dkr.ecr.<region>.amazonaws.com
	return strings.Contains(host, ".amazonaws.com") && strings.Contains(host, ".ecr.")
}

func isACRHost(host string) bool {
	// *.azurecr.io
	return strings.HasSuffix(host, ".azurecr.io")
}

// NewExplicitKeychain returns a keychain where the supplied username/password
// take highest priority, falling back to NewKeychain() for all other registries.
func NewExplicitKeychain(username, password string) authn.Keychain {
	static := &staticKeychain{
		auth: authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		}),
	}
	return authn.NewMultiKeychain(static, NewKeychain())
}

// staticKeychain wraps a single Authenticator and returns it for every resource.
type staticKeychain struct {
	auth authn.Authenticator
}

func (s *staticKeychain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return s.auth, nil
}

// DetectAuthSource probes the keychain to determine which credential source
// would be used for imageRef. Used by the CLI to print the "Auth:" line.
// Does not actually pull the image.
func DetectAuthSource(imageRef string, kc authn.Keychain, isExplicit bool) AuthSource {
	if isExplicit {
		return AuthExplicit
	}
	if kc == nil {
		return AuthAnonymous
	}

	// Strip tag/digest to get a bare repository for Resolve().
	ref := imageRef
	if i := lastIndexByte(ref, '@'); i > 0 {
		ref = ref[:i]
	} else if i := lastIndexByte(ref, ':'); i > lastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	repo, err := name.NewRepository(ref)
	if err != nil {
		return AuthAnonymous
	}

	host := repo.RegistryStr()
	switch {
	case isECRHost(host):
		return AuthECR
	case isACRHost(host):
		return AuthACR
	}

	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return AuthAnonymous
	}
	cfg, err := auth.Authorization()
	if err != nil {
		return AuthAnonymous
	}
	if cfg.Username != "" || cfg.RegistryToken != "" || cfg.Auth != "" {
		return AuthDockerConfig
	}
	return AuthAnonymous
}

// lastIndexByte returns the last index of b in s, or -1.
func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
