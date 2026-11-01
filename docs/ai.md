# Optional AI helpers

`github.com/tracepod/tracepod/ai` is a small, provider-agnostic LLM client for
optional helpers in `harden`. **Nothing calls a model unless you configure one**:
`ai.New(ai.Config{})` (or `Provider: "off"`) returns a provider whose `Complete`
returns `ai.ErrDisabled` without touching the network. The sensor does not
import this package.

## Providers

| `Config.Provider`   | Backend                                              | Package          |
|---------------------|------------------------------------------------------|------------------|
| `off` (default)     | none                                                 | `ai`             |
| `openai-compatible` | vLLM, Ollama, LiteLLM, OpenAI-style gateways         | `ai`             |
| `anthropic`         | Anthropic API (optionally via a gateway `BaseURL`)   | `ai/anthropic`   |
| `bedrock`           | Anthropic models on Amazon Bedrock                   | `ai/anthropic`   |
| `vertex`            | Anthropic models on Google Vertex AI                 | `ai/anthropic`   |

The Anthropic adapter is a separate package so its SDK and cloud-auth
dependencies are linked only into binaries that import it:

```go
import (
    "github.com/tracepod/tracepod/ai"
    _ "github.com/tracepod/tracepod/ai/anthropic" // registers anthropic, bedrock, vertex
)

p, err := ai.New(ai.Config{Provider: "openai-compatible", BaseURL: "http://localhost:11434/v1", ModelFast: "qwen2.5:7b-instruct"})
p = ai.WithRedaction(p)
```

Credentials are never read or logged by this package. The Anthropic API uses
`ANTHROPIC_API_KEY` (or `Config.APIKey`); Bedrock uses the AWS default chain
(environment, profile, IRSA, EKS Pod Identity); Vertex uses Google Application
Default Credentials. Model IDs are configuration (`ModelFast`, `ModelStrong`);
Anthropic-family providers default to `claude-haiku-5-5` / `claude-sonnet-5-5`
(with an `anthropic.` prefix on Bedrock). The OpenAI-compatible provider has no
default model. `temperature` is never sent and tool choice is never forced.

## Structured answers

`ai.CompleteJSON[T]` asks for JSON, checks it against `Request.Schema` (a built-in
validator for the common JSON Schema subset) and an optional Go validation
function, and retries once with the error appended to the conversation. A second
failure returns `ai.ErrInvalidOutput`. A refusal (`ai.ErrRefused`) or a truncated
answer (`ai.ErrTruncated`) is returned as-is: treat both as "no suggestion".
When the endpoint supports it the schema is sent natively (`response_format` for
OpenAI-compatible endpoints, `output_config.format` for Anthropic); with
`StructuredOutput: "auto"` an endpoint that rejects `response_format` is retried
once in prompt-only mode and remembered for the process. Responses are always
validated in Go.

## Redaction

`ai.Redact` replaces private keys, URL credentials, JWTs, bearer tokens, AWS
keys, GitHub / GitLab / Slack tokens, `password|secret|token|api_key`
assignments, email addresses and IPv4 addresses with `[REDACTED]`;
`ai.WithRedaction` applies it to every system prompt and message. Inputs larger
than `MaxInputBytes` (default 200 KB) are truncated from the middle.

## Candidates

`ai/candidates` is pure Go and never calls a model. Given the `inventory.json`
written by `harden build` and a workload's log text, `candidates.Generate`
returns a ranked, capped list of paths that exist in the source image but not in
the hardened image and that the logs refer to (quoted path 100, basename 80,
path-segment 60, stem 40; symlink targets follow their link). A model may only
select among these paths, never invent new ones.

```go
entries, _ := candidates.LoadInventory(f) // {"version":2,"files":[...]} (version 1 is also accepted)
cands := candidates.Generate(entries, logs, candidates.Options{Max: 50})
```
