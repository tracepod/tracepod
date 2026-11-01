package ai

import (
	"context"
	"regexp"
	"strings"
)

// RedactedPlaceholder replaces every secret-looking span.
const RedactedPlaceholder = "[REDACTED]"

type redactRule struct {
	re   *regexp.Regexp
	repl string
}

// Order matters: structured credentials first, generic key=value last.
var redactRules = []redactRule{
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), RedactedPlaceholder},
	{regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@:]+:[^\s/@]*@`), "${1}" + RedactedPlaceholder + "@"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`), RedactedPlaceholder},
	{regexp.MustCompile(`(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} " + RedactedPlaceholder},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), RedactedPlaceholder},
	{regexp.MustCompile(`(?i)(aws_?secret[\w]*["']?\s*[=:]\s*["']?)[A-Za-z0-9/+=]{40}\b`), "${1}" + RedactedPlaceholder},
	{regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`), RedactedPlaceholder},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{16,}`), RedactedPlaceholder},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), RedactedPlaceholder},
	// password / secret / token / api key assignments. The leading group keeps
	// path separators and identifier characters from matching ("/run/secrets/x").
	{regexp.MustCompile(`(?i)(^|[^\w/.-])((?:password|passwd|secret|token|api[_-]?key)["']?\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;&"']+)`), "${1}${2}" + RedactedPlaceholder},
	{regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`), RedactedPlaceholder},
}

var ipv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)

// Redact replaces credentials and other identifying material in s with
// "[REDACTED]": private-key blocks, URL credentials, JWTs, bearer tokens, AWS
// access keys and secrets, GitHub / GitLab / Slack tokens, password / secret /
// token / api-key assignments, email addresses and IPv4 addresses. File paths
// are left alone.
func Redact(s string) string {
	for _, r := range redactRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return redactIPv4(s)
}

func redactIPv4(s string) string {
	locs := ipv4.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		start, end := l[0], l[1]
		// Skip dotted runs longer than four groups (versions, OIDs).
		if start > 0 && s[start-1] == '.' && start > 1 && isDigit(s[start-2]) {
			continue
		}
		if end+1 < len(s) && s[end] == '.' && isDigit(s[end+1]) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(RedactedPlaceholder)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

type redacting struct{ p Provider }

// WithRedaction wraps p so that the system prompt and every message are passed
// through Redact before being sent.
func WithRedaction(p Provider) Provider { return redacting{p} }

func (r redacting) Name() string { return r.p.Name() }

func (r redacting) Complete(ctx context.Context, req Request) (Response, error) {
	req.System = Redact(req.System)
	msgs := make([]Message, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = Message{Role: m.Role, Text: Redact(m.Text)}
	}
	req.Messages = msgs
	return r.p.Complete(ctx, req)
}
