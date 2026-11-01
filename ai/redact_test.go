package ai

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	secrets := map[string]string{
		"aws access key": "key AKIAIOSFODNN7EXAMPLE used",
		"aws temp key":   "ASIAIOSFODNN7EXAMPLE",
		"aws secret":     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"bearer":         "Authorization: Bearer abcDEF123456.xyz-_~+/=",
		"jwt":            "token " + jwt,
		"private key":    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----",
		"private key ec": "-----BEGIN PRIVATE KEY-----\nMIIEow\n-----END PRIVATE KEY-----",
		"url creds":      "postgres://admin:s3cr3t@db.internal:5432/app",
		"password eq":    "password=hunter2",
		"password colon": `{"password": "hunter two"}`,
		"passwd":         "passwd: hunter2",
		"secret":         "SECRET=abcd1234",
		"token":          "token = abc123",
		"api key":        "api_key=abc123",
		"api-key":        "API-KEY: abc123",
		"apikey":         "apikey=abc123",
		"github pat":     "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"github fine":    "github_pat_11ABCDEFG0abcdefghijklmnop",
		"gitlab":         "glpat-abcdefghijklmnopqrst",
		"slack":          "xoxb-1234567890-abcdefghij",
		"email":          "contact bob.smith+x@example.co.uk now",
		"ipv4":           "connect to 192.168.10.25:5432",
		"ipv4 loopback":  "dial 127.0.0.1",
	}
	needles := map[string]string{
		"aws access key": "AKIAIOSFODNN7EXAMPLE", "aws temp key": "ASIAIOSFODNN7EXAMPLE",
		"aws secret": "wJalrXUtnFEMI", "bearer": "abcDEF123456", "jwt": "eyJhbGci",
		"private key": "MIIEow", "private key ec": "MIIEow", "url creds": "s3cr3t",
		"password eq": "hunter2", "password colon": "hunter two", "passwd": "hunter2",
		"secret": "abcd1234", "token": "abc123", "api key": "abc123", "api-key": "abc123", "apikey": "abc123",
		"github pat": "ghp_", "github fine": "github_pat_", "gitlab": "glpat-", "slack": "xoxb-",
		"email": "bob.smith", "ipv4": "192.168.10.25", "ipv4 loopback": "127.0.0.1",
	}
	for name, in := range secrets {
		got := Redact(in)
		if strings.Contains(got, needles[name]) || !strings.Contains(got, RedactedPlaceholder) {
			t.Errorf("%s: %q -> %q", name, in, got)
		}
	}
}

func TestRedactKeepsStructure(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://admin:s3cr3t@db:5432/x": "postgres://[REDACTED]@db:5432/x",
		"password=hunter2 rest":             "password=[REDACTED] rest",
		"Bearer abcdefgh12345":              "Bearer [REDACTED]",
		"host 10.1.2.3 down":                "host [REDACTED] down",
	} {
		if got := Redact(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestRedactFalsePositiveGuards(t *testing.T) {
	for _, in := range []string{
		`open() "/etc/nginx/mime.types" failed (2: No such file or directory)`,
		"open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory",
		"/etc/ssl/private/server.key not found",
		"ModuleNotFoundError: No module named 'yaml.constructor'",
		"libfoo.so.1.2.3: cannot open shared object file",
		"python 3.12.1 and v1.2.3.4.5 and 1.2.3.4.5",
		"Cannot find module '@scope/pkg' in /app/node_modules",
		"the token bucket was empty",
		"java.lang.ClassNotFoundException: com.acme.Widget",
		"Bearer tokens are supported",
		"-----BEGIN CERTIFICATE----- is public",
		"GET /api/v1/profiles 200",
		"/usr/lib/secret/lib.so",
	} {
		if got := Redact(in); got != in {
			t.Errorf("false positive:\n in:  %q\n out: %q", in, got)
		}
	}
}

func TestRedactIdempotent(t *testing.T) {
	in := "password=x AKIAIOSFODNN7EXAMPLE 1.2.3.4 a@b.io"
	once := Redact(in)
	if Redact(once) != once {
		t.Fatalf("not idempotent: %q", once)
	}
}
