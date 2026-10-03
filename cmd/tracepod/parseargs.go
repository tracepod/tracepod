package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// parseInterspersed parses args against fs, allowing flags and positional
// arguments to appear in any order (Go's flag package otherwise stops
// parsing flags at the first non-flag argument, which breaks the documented
// `tracepod cve-report TARGET --flag value` form). It repeatedly calls
// fs.Parse on the remaining arguments, peeling off one positional at a time
// between flag runs, and returns the full list of positionals in the order
// they appeared.
//
// "--" ends flag parsing early, same as flag.Parse: everything after it is
// treated as positional, even if it looks like a flag. Note one unavoidable
// edge case shared with flag.Parse itself: "--" immediately after a flag
// that takes a value (e.g. "--findings -- foo") is consumed as that flag's
// *value*, not as end-of-flags — this helper can't distinguish the two
// without knowing the flag's arity ahead of time, which is exactly what
// flag.Parse already can't do either.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()

		// Detect an explicit "--" that flag.Parse consumed: the number of
		// args it ate is one more than what's left, and the last-eaten
		// token was "--".
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positionals, rest...), nil
		}

		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// errUnexpectedArgs marks a stray-positional failure for a subcommand that
// takes no positional arguments, so callers can give it exit code 1 —
// distinct from a flag.Parse failure (unknown flag, bad value), which keeps
// exit code 2 per flag's own ExitOnError convention.
var errUnexpectedArgs = errors.New("unexpected argument")

// parseNoPositionals parses args against fs (flags only, in any order, via
// parseInterspersed) for a subcommand that takes no positional arguments. It
// returns a non-nil error wrapping errUnexpectedArgs if any positional is
// left over.
func parseNoPositionals(fs *flag.FlagSet, args []string) error {
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("%s: %w %q", fs.Name(), errUnexpectedArgs, rest[0])
	}
	return nil
}

// exitForArgError maps an error from parseNoPositionals to this CLI's
// established exit codes: 0 for -h/--help, 1 for a stray positional argument
// (the error message is printed, followed by usage), 2 for any other
// flag.Parse failure (unknown flag, bad value) — matching flag's own
// ExitOnError convention.
func exitForArgError(err error, usage string) {
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	case errors.Is(err, errUnexpectedArgs):
		fmt.Fprintf(os.Stderr, "tracepod %v\n", err)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	default:
		os.Exit(2)
	}
}
