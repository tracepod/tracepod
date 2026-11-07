package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/tracepod/tracepod/ai"
)

// Optional AI helpers for `harden explain` and `harden diagnose`.
//
// Configuration comes from the environment, or from the --ai-* flags, and is
// never written anywhere. API keys are read from the environment only: a key
// on the command line would end up in shell history and process listings.
//
// The harden binary links only the OpenAI-compatible adapter from the ai
// package. The Anthropic API is reached through its OpenAI-compatible
// endpoint, so the Anthropic SDK and the AWS / Google SDKs it pulls in (about
// 30 MB) stay out of this binary. Amazon Bedrock and Google Vertex AI are
// supported through an OpenAI-compatible gateway such as LiteLLM.

// Environment variables read by aiConfigFromEnv.
const (
	envAIProvider = "TRACEPOD_AI_PROVIDER"
	envAIBaseURL  = "TRACEPOD_AI_BASE_URL"
	envAIAPIKey   = "TRACEPOD_AI_API_KEY"
	envAIModel    = "TRACEPOD_AI_MODEL"
	envAnthropic  = "ANTHROPIC_API_KEY"
)

// Defaults for TRACEPOD_AI_PROVIDER=anthropic.
const (
	anthropicCompatBaseURL = "https://api.anthropic.com/v1"
	anthropicDefaultModel  = "claude-haiku-5-5"
)

// aiFlags are the per-command overrides for the environment. There is
// deliberately no API key flag.
type aiFlags struct {
	noAI     bool
	provider string
	baseURL  string
	model    string
}

func (f *aiFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.noAI, "no-ai", false, "Do not call a model, even if one is configured (deterministic output only)")
	fs.StringVar(&f.provider, "ai-provider", "", "Model provider: off, openai-compatible or anthropic (default: $"+envAIProvider+", else off)")
	fs.StringVar(&f.baseURL, "ai-base-url", "", "OpenAI-compatible endpoint, e.g. http://localhost:11434/v1 (default: $"+envAIBaseURL+")")
	fs.StringVar(&f.model, "ai-model", "", "Model identifier (default: $"+envAIModel+")")
}

// errAIConfig marks a configuration error (exit 2).
var errAIConfig = errors.New("AI configuration")

// newAIProvider returns the configured provider and model name, or a nil
// provider when AI is off. The provider redacts every prompt before it is
// sent. client may be nil.
func newAIProvider(f aiFlags, getenv func(string) string, client *http.Client) (ai.Provider, string, error) {
	if f.noAI {
		return nil, "", nil
	}
	pick := func(flagVal, env string) string {
		if flagVal != "" {
			return flagVal
		}
		return strings.TrimSpace(getenv(env))
	}
	provider := strings.ToLower(pick(f.provider, envAIProvider))
	cfg := ai.Config{
		BaseURL:    pick(f.baseURL, envAIBaseURL),
		APIKey:     strings.TrimSpace(getenv(envAIAPIKey)),
		HTTPClient: client,
	}
	model := pick(f.model, envAIModel)

	switch provider {
	case "", ai.ProviderOff:
		return nil, "", nil
	case ai.ProviderOpenAICompatible:
		if cfg.BaseURL == "" {
			return nil, "", fmt.Errorf("%w: %s=openai-compatible requires %s (or --ai-base-url)", errAIConfig, envAIProvider, envAIBaseURL)
		}
		if model == "" {
			return nil, "", fmt.Errorf("%w: %s=openai-compatible requires %s (or --ai-model)", errAIConfig, envAIProvider, envAIModel)
		}
		cfg.Provider = ai.ProviderOpenAICompatible
	case ai.ProviderAnthropic:
		if cfg.APIKey == "" {
			cfg.APIKey = strings.TrimSpace(getenv(envAnthropic))
		}
		if cfg.APIKey == "" {
			return nil, "", fmt.Errorf("%w: %s=anthropic requires %s or %s", errAIConfig, envAIProvider, envAIAPIKey, envAnthropic)
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = anthropicCompatBaseURL
		}
		if model == "" {
			model = anthropicDefaultModel
		}
		cfg.Provider = ai.ProviderOpenAICompatible
		// The schema goes in the prompt; the answer is validated in Go either way.
		cfg.StructuredOutput = ai.StructuredOff
	case ai.ProviderBedrock, ai.ProviderVertex:
		return nil, "", fmt.Errorf("%w: provider %q is not built into harden; point %s=openai-compatible at an OpenAI-compatible gateway (for example LiteLLM) in front of it", errAIConfig, provider, envAIProvider)
	default:
		return nil, "", fmt.Errorf("%w: unknown provider %q (want off, openai-compatible or anthropic)", errAIConfig, provider)
	}
	cfg.ModelFast, cfg.ModelStrong = model, model

	p, err := ai.New(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errAIConfig, err)
	}
	return ai.WithRedaction(p), model, nil
}

// aiMaxTokens bounds each answer. The answers themselves are short; the
// headroom is for reasoning models, whose hidden reasoning counts against it.
const aiMaxTokens = 4096
