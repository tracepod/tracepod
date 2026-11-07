# Optional AI helpers

`github.com/tracepod/tracepod/ai` is a small, provider-agnostic LLM client for
the optional helpers in `harden` (`harden explain`, `harden diagnose`). **Nothing calls a model unless you configure one**:
`ai.New(ai.Config{})` (or `Provider: "off"`) returns a provider whose `Complete`
returns `ai.ErrDisabled` without touching the network. The sensor does not
import this package.

## In the `harden` CLI

`harden explain` and `harden diagnose` (see the README) work without a model.
With one configured, `diagnose` lets it pick among the weaker log matches and
`explain` adds a short plain-English summary. You bring your own model and
credentials.

| Variable / flag                              | Meaning |
|----------------------------------------------|---------|
| `TRACEPOD_AI_PROVIDER` / `--ai-provider`     | `off` (default), `openai-compatible` or `anthropic` |
| `TRACEPOD_AI_BASE_URL` / `--ai-base-url`     | OpenAI-compatible endpoint, e.g. `http://localhost:11434/v1`. For `anthropic`, defaults to `https://api.anthropic.com/v1` |
| `TRACEPOD_AI_MODEL` / `--ai-model`           | Model identifier. Required for `openai-compatible`; `anthropic` defaults to `claude-haiku-5-5` |
| `TRACEPOD_AI_API_KEY`                        | Sent as a bearer token. For `anthropic`, falls back to `ANTHROPIC_API_KEY` |
| `--no-ai`                                    | Do not call a model for this run |

- **Off by default.** With no provider set, or with `--no-ai`, the commands make
  no network calls at all.
- **Keys come from the environment only.** There is no key flag (a key on the
  command line ends up in shell history and process listings). Nothing is written
  to disk.
- **What is sent.** `diagnose` sends the container log (redacted, at most 16 KB
  of it) and the candidate list (paths and the matching log lines). It calls the
  model only when there are weaker matches to rank. `explain` sends only its own
  deterministic summary (counts, package names, example paths), never file
  contents. Everything passes through `ai.Redact` first.
- **Answers are checked.** A `diagnose` answer must pick at most 10 paths, each
  from the candidate list; otherwise it is retried once and then dropped, and the
  deterministic suggestions are printed alone. An `explain` summary over 150 words,
  or one that names a path or quoted name not in the summary it was given, is
  dropped with a note.
- **Errors never fail the command.** A refusal, a timeout or an HTTP error prints
  a note and the deterministic output; the exit code stays 0.

`harden` links only the OpenAI-compatible adapter. The `anthropic` provider uses
the Anthropic API's OpenAI-compatible endpoint, with the JSON schema given in the
prompt (answers are validated in Go either way). Linking `ai/anthropic` would add
about 30 MB to the binary (the Anthropic, AWS and Google SDKs) for Bedrock and
Vertex AI, so `harden` does not offer those providers directly: put an
OpenAI-compatible gateway such as LiteLLM in front of them and use
`openai-compatible`. Programs that import the `ai` package can still use every
provider below.

Examples:

```bash
# Ollama
TRACEPOD_AI_PROVIDER=openai-compatible TRACEPOD_AI_BASE_URL=http://localhost:11434/v1 \
  TRACEPOD_AI_MODEL=qwen2.5:7b-instruct harden diagnose --output out --log out/smoke.log

# OpenRouter (or any hosted OpenAI-compatible API)
TRACEPOD_AI_PROVIDER=openai-compatible TRACEPOD_AI_BASE_URL=https://openrouter.ai/api/v1 \
  TRACEPOD_AI_MODEL=<model id> TRACEPOD_AI_API_KEY=... harden explain --output out

# Anthropic API
TRACEPOD_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=... harden diagnose --output out --log app.log
```

Reasoning models count their hidden reasoning against the answer limit; the CLI
allows 4096 output tokens per call.

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
