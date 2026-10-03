package main

import (
	"errors"
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"
)

// TestParseInterspersed covers the ordering combinations that Go's flag
// package otherwise gets wrong: flags before a positional (its native
// behaviour), flags after a positional (the bug this helper fixes), flags on
// both sides, and an explicit "--" terminator.
func TestParseInterspersed(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string, *bool) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		s := fs.String("findings", "", "")
		v := fs.Bool("verbose", false, "")
		return fs, s, v
	}

	cases := []struct {
		name         string
		args         []string
		wantPos      []string
		wantFindings string
		wantVerbose  bool
	}{
		{
			name:         "flags before positional",
			args:         []string{"--findings", "f.json", "--verbose", "target"},
			wantPos:      []string{"target"},
			wantFindings: "f.json",
			wantVerbose:  true,
		},
		{
			name:         "flags after positional",
			args:         []string{"target", "--findings", "f.json", "--verbose"},
			wantPos:      []string{"target"},
			wantFindings: "f.json",
			wantVerbose:  true,
		},
		{
			name:         "flags on both sides",
			args:         []string{"--verbose", "target", "--findings", "f.json"},
			wantPos:      []string{"target"},
			wantFindings: "f.json",
			wantVerbose:  true,
		},
		{
			name:    "double-dash ends flag parsing",
			args:    []string{"--verbose", "--", "--findings", "target"},
			wantPos: []string{"--findings", "target"},
			// --verbose was consumed before "--"; "--findings" and "target"
			// are positional, left as literal strings.
			wantVerbose: true,
		},
		{
			name:    "no flags at all",
			args:    []string{"target"},
			wantPos: []string{"target"},
		},
		{
			name:    "no args at all",
			args:    []string{},
			wantPos: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, findings, verbose := newFS()
			got, err := parseInterspersed(fs, tc.args)
			if err != nil {
				t.Fatalf("parseInterspersed() error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.wantPos) {
				t.Errorf("positionals = %#v, want %#v", got, tc.wantPos)
			}
			if *findings != tc.wantFindings {
				t.Errorf("findings = %q, want %q", *findings, tc.wantFindings)
			}
			if *verbose != tc.wantVerbose {
				t.Errorf("verbose = %v, want %v", *verbose, tc.wantVerbose)
			}
		})
	}
}

// TestParseInterspersed_UnknownFlag ensures an unrecognized flag still
// surfaces a parse error, with or without a positional already consumed.
func TestParseInterspersed_UnknownFlag(t *testing.T) {
	cases := [][]string{
		{"target", "--nope"},
		{"--nope", "target"},
	}
	for _, args := range cases {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.String("findings", "", "")
		_, err := parseInterspersed(fs, args)
		if err == nil {
			t.Errorf("parseInterspersed(%v): want error for unknown flag, got nil", args)
		}
	}
}

// TestParseCVEReportArgs covers the full cve-report flag set through the
// public entry point used by runCVEReport.
func TestParseCVEReportArgs(t *testing.T) {
	t.Run("flags after target", func(t *testing.T) {
		opts, err := parseCVEReportArgs([]string{"my-app", "--findings", "f.json", "--verbose"}, io.Discard)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.target != "my-app" || opts.findings != "f.json" || !opts.verbose {
			t.Errorf("opts = %+v", opts)
		}
	})

	t.Run("flags before target", func(t *testing.T) {
		opts, err := parseCVEReportArgs([]string{"--findings", "f.json", "--verbose", "my-app"}, io.Discard)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.target != "my-app" || opts.findings != "f.json" || !opts.verbose {
			t.Errorf("opts = %+v", opts)
		}
	})

	t.Run("mixed", func(t *testing.T) {
		opts, err := parseCVEReportArgs([]string{"--verbose", "my-app", "--findings", "f.json", "--severity", "high"}, io.Discard)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.target != "my-app" || opts.findings != "f.json" || opts.severity != "high" || !opts.verbose {
			t.Errorf("opts = %+v", opts)
		}
	})

	t.Run("double dash before target", func(t *testing.T) {
		opts, err := parseCVEReportArgs([]string{"--verbose", "--", "my-app"}, io.Discard)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.target != "my-app" || !opts.verbose {
			t.Errorf("opts = %+v", opts)
		}
	})

	t.Run("missing target", func(t *testing.T) {
		_, err := parseCVEReportArgs([]string{"--verbose"}, io.Discard)
		if err == nil {
			t.Fatal("want error for missing target, got nil")
		}
	})

	t.Run("too many positionals", func(t *testing.T) {
		_, err := parseCVEReportArgs([]string{"my-app", "extra"}, io.Discard)
		if err == nil {
			t.Fatal("want error for extra positional, got nil")
		}
	})

	t.Run("unknown flag", func(t *testing.T) {
		_, err := parseCVEReportArgs([]string{"my-app", "--nope"}, io.Discard)
		if err == nil {
			t.Fatal("want error for unknown flag, got nil")
		}
		if errors.Is(err, flag.ErrHelp) {
			t.Fatal("unknown flag should not be flag.ErrHelp")
		}
	})

	t.Run("help flag", func(t *testing.T) {
		_, err := parseCVEReportArgs([]string{"-h"}, io.Discard)
		if !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("err = %v, want flag.ErrHelp", err)
		}
	})
}

// TestParseNoPositionals covers subcommands that take no positional
// argument (profile list/get/stop): flags-only input must keep working in
// any order, and a stray positional — before or after the flags — must be
// rejected rather than silently truncating flag parsing (the second CLI
// bug: `tracepod profile list foo --namespace prod` used to drop
// --namespace).
func TestParseNoPositionals(t *testing.T) {
	cases := []struct {
		name          string
		args          []string
		wantNoErr     bool  // true: parseNoPositionals must return nil
		wantErrIs     error // non-nil: err must satisfy errors.Is(err, wantErrIs)
		wantPlainErr  bool  // true: err must be non-nil but NOT errUnexpectedArgs/flag.ErrHelp
		wantErrSubstr string
		wantNS        string // expected --namespace value after parsing, regardless of outcome
	}{
		{
			name:      "flags only",
			args:      []string{"--namespace", "prod"},
			wantNoErr: true,
			wantNS:    "prod",
		},
		{
			name:      "no args at all",
			args:      []string{},
			wantNoErr: true,
		},
		{
			name:          "stray positional after flags",
			args:          []string{"--namespace", "prod", "foo"},
			wantErrIs:     errUnexpectedArgs,
			wantErrSubstr: `"foo"`,
			wantNS:        "prod", // the flag was parsed before the positional was rejected
		},
		{
			name:          "stray positional before flags",
			args:          []string{"foo", "--namespace", "prod"},
			wantErrIs:     errUnexpectedArgs,
			wantErrSubstr: `"foo"`,
			wantNS:        "prod",
		},
		{
			name:          "stray positional only",
			args:          []string{"foo"},
			wantErrIs:     errUnexpectedArgs,
			wantErrSubstr: `"foo"`,
		},
		{
			name:         "unknown flag",
			args:         []string{"--nope"},
			wantPlainErr: true,
		},
		{
			name:      "help flag",
			args:      []string{"-h"},
			wantErrIs: flag.ErrHelp,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			ns := fs.String("namespace", "", "")

			err := parseNoPositionals(fs, tc.args)

			switch {
			case tc.wantNoErr:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case tc.wantPlainErr:
				if err == nil {
					t.Fatal("want a plain flag.Parse error, got nil")
				}
				if errors.Is(err, errUnexpectedArgs) || errors.Is(err, flag.ErrHelp) {
					t.Fatalf("err = %v, want a plain flag.Parse failure", err)
				}
			case tc.wantErrIs != nil:
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is(_, %v)", err, tc.wantErrIs)
				}
			}

			if tc.wantErrSubstr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr)) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErrSubstr)
			}
			if *ns != tc.wantNS {
				t.Errorf("namespace = %q, want %q", *ns, tc.wantNS)
			}
		})
	}
}
