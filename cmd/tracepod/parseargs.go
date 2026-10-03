package main

import "flag"

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
