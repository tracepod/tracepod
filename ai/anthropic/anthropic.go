// Package anthropic is the ai.Provider adapter for Claude models, reached
// through the Anthropic API, Amazon Bedrock or Google Vertex AI.
//
// It lives in its own package so that the Anthropic SDK and its AWS / Google
// authentication dependencies are linked only into binaries that import it.
// Importing the package registers the "anthropic", "bedrock" and "vertex"
// providers with ai.New:
//
//	import _ "github.com/tracepod/tracepod/ai/anthropic"
//
// Credentials come from the SDK default chains and are never read or logged by
// this package: ANTHROPIC_API_KEY (or Config.APIKey) for the Anthropic API, the
// AWS default chain (environment, shared profile, web identity / IRSA, EKS Pod
// Identity) for Bedrock, and Google Application Default Credentials for Vertex.
package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/bedrock"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	"github.com/anthropics/anthropic-sdk-go/v2/vertex"

	"github.com/tracepod/tracepod/ai"
)

// Default model identifiers.
const (
	DefaultFast   = "claude-haiku-5-5"
	DefaultStrong = "claude-sonnet-5-5"
	// BedrockPrefix is prepended to the defaults on Bedrock.
	BedrockPrefix = "anthropic."
)

func init() {
	for _, name := range []string{ai.ProviderAnthropic, ai.ProviderBedrock, ai.ProviderVertex} {
		ai.Register(name, New)
	}
}

// messageAPI is the slice of the SDK's MessageService used here.
type messageAPI interface {
	New(ctx context.Context, params sdk.MessageNewParams, opts ...option.RequestOption) (*sdk.Message, error)
}

type provider struct {
	name string
	cfg  ai.Config
	api  messageAPI
}

// New builds an Anthropic, Bedrock or Vertex provider from cfg.Provider.
func New(cfg ai.Config) (ai.Provider, error) {
	cfg = cfg.WithDefaults()
	fast, strong := DefaultFast, DefaultStrong
	if cfg.Provider == ai.ProviderBedrock {
		fast, strong = BedrockPrefix+fast, BedrockPrefix+strong
	}
	if cfg.ModelFast == "" {
		cfg.ModelFast = fast
	}
	if cfg.ModelStrong == "" {
		cfg.ModelStrong = strong
	}
	ctx := context.Background()
	var api messageAPI
	switch cfg.Provider {
	case ai.ProviderAnthropic:
		opts := []option.RequestOption{}
		if cfg.APIKey != "" {
			opts = append(opts, option.WithAPIKey(cfg.APIKey))
		}
		if cfg.BaseURL != "" {
			opts = append(opts, option.WithBaseURL(cfg.BaseURL))
		}
		c := sdk.NewClient(opts...)
		api = &c.Messages
	case ai.ProviderBedrock:
		c, err := bedrock.NewMantleClient(ctx, bedrock.MantleClientConfig{
			AWSRegion: cfg.Region,
			BaseURL:   cfg.BaseURL,
		})
		if err != nil {
			return nil, fmt.Errorf("ai: bedrock client: %w", err)
		}
		api = &c.Messages
	case ai.ProviderVertex:
		if cfg.Region == "" {
			return nil, errors.New("ai: vertex provider requires Region")
		}
		opt, err := vertexAuth(ctx, cfg.Region, cfg.ProjectID)
		if err != nil {
			return nil, err
		}
		c := sdk.NewClient(opt)
		api = &c.Messages
	default:
		return nil, fmt.Errorf("ai: anthropic adapter cannot serve provider %q", cfg.Provider)
	}
	return &provider{name: cfg.Provider, cfg: cfg, api: api}, nil
}

// vertexAuth converts the SDK's panic on missing credentials into an error.
func vertexAuth(ctx context.Context, region, project string) (opt option.RequestOption, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ai: vertex credentials: %v", r)
		}
	}()
	return vertex.WithGoogleAuth(ctx, region, project), nil
}

func (p *provider) Name() string { return p.name }

func (p *provider) Complete(ctx context.Context, req ai.Request) (ai.Response, error) {
	req = p.cfg.Prepare(req)
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	params, err := p.params(req)
	if err != nil {
		return ai.Response{}, err
	}
	msg, err := p.api.New(ctx, params)
	if err != nil {
		var apiErr *sdk.Error
		if errors.As(err, &apiErr) {
			return ai.Response{}, &ai.APIError{StatusCode: apiErr.StatusCode, Message: ai.ErrorMessage([]byte(apiErr.RawJSON()))}
		}
		return ai.Response{}, fmt.Errorf("ai: %s request failed: %w", p.name, err)
	}
	var text strings.Builder
	for _, b := range msg.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	resp := ai.Response{
		Text:         text.String(),
		Model:        string(msg.Model),
		StopReason:   string(msg.StopReason),
		InputTokens:  int(msg.Usage.InputTokens),
		OutputTokens: int(msg.Usage.OutputTokens),
	}
	switch msg.StopReason {
	case sdk.StopReasonRefusal:
		return resp, ai.ErrRefused
	case sdk.StopReasonMaxTokens:
		return resp, ai.ErrTruncated
	}
	return resp, nil
}

func (p *provider) params(req ai.Request) (sdk.MessageNewParams, error) {
	params := sdk.MessageNewParams{
		Model:     sdk.Model(p.cfg.ModelFor(req.Tier)),
		MaxTokens: int64(req.MaxTokens),
	}
	// Deliberately no temperature and no forced tool_choice.
	if req.System != "" {
		params.System = []sdk.TextBlockParam{{Text: req.System}}
	}
	for _, m := range req.Messages {
		block := sdk.NewTextBlock(m.Text)
		switch m.Role {
		case "assistant":
			params.Messages = append(params.Messages, sdk.NewAssistantMessage(block))
		case "user", "":
			params.Messages = append(params.Messages, sdk.NewUserMessage(block))
		default:
			return params, fmt.Errorf("ai: unsupported message role %q", m.Role)
		}
	}
	if req.Tier == ai.TierFast {
		params.OutputConfig.Effort = sdk.OutputConfigEffortLow
	}
	if len(req.Schema) > 0 && p.cfg.StructuredOutput != ai.StructuredOff {
		var schema map[string]any
		if err := json.Unmarshal(req.Schema, &schema); err != nil {
			return params, fmt.Errorf("ai: invalid schema: %w", err)
		}
		params.OutputConfig.Format = sdk.JSONOutputFormatParam{Schema: schema}
	} else if len(req.Schema) > 0 {
		sys := strings.TrimSpace(req.System + "\n\n" + ai.SchemaInstruction(req.Schema))
		params.System = []sdk.TextBlockParam{{Text: sys}}
	}
	return params, nil
}
