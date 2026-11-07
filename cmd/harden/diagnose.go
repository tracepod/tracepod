package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tracepod/tracepod/ai"
	"github.com/tracepod/tracepod/ai/candidates"
	"github.com/tracepod/tracepod/hardener"
)

// Limits for `harden diagnose`.
const (
	diagnoseMaxLogBytes    = 200 * 1024 // log read size; larger logs are middle-truncated
	diagnoseMaxCandidates  = 200
	diagnoseMaxPicks       = 10
	diagnosePromptLogBytes = 16 * 1024 // log excerpt sent to the model
	diagnosePromptCands    = 100       // candidates sent to the model
)

// diagnoseSuggestion is one path to add with --include.
type diagnoseSuggestion struct {
	Path     string `json:"path"`
	Source   string `json:"source"` // "deterministic" or "model"
	Match    string `json:"match"`
	Evidence string `json:"evidence,omitempty"` // redacted log line
	// Flag is the harden build flag that restores the path: "--include", or
	// "--mkdir" for a source directory with no files beneath it (--include
	// only copies files, so it would leave an empty directory out).
	Flag string `json:"flag"`
}

type diagnoseOutput struct {
	Suggestions []diagnoseSuggestion `json:"suggestions"`
	Candidates  int                  `json:"candidates"`
	Model       string               `json:"model,omitempty"`
	Note        string               `json:"note,omitempty"`
	Rerun       string               `json:"rerun,omitempty"`
}

const diagnoseNothingFound = "No file-related cause found — the failure may be environmental (network, credentials, config)"

func runDiagnose(args []string) int { return runDiagnoseWith(args, osCmdEnv()) }

func runDiagnoseWith(args []string, env cmdEnv) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var (
		outputDir     = fs.String("output", "", "Output directory of the `harden build` that produced the failing image")
		logPath       = fs.String("log", "", "Log of the failing container, or - for stdin (required)")
		inventoryPath = fs.String("inventory", "", "Path to inventory.json if the build used --inventory-out (default: <output>/inventory.json)")
		asJSON        = fs.Bool("json", false, "Print JSON instead of text")
		af            aiFlags
	)
	af.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.stderr, "Usage: harden diagnose --output <dir> --log <file|-> [--inventory <file>] [--json] [--no-ai]")
		fmt.Fprintln(env.stderr, "\nSuggest --include flags for a hardened image that fails at runtime. Suggestions are only ever")
		fmt.Fprintln(env.stderr, "paths that exist in the source image and were removed by the build. Nothing is rebuilt.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *logPath == "" || (*outputDir == "" && *inventoryPath == "") {
		fs.Usage()
		fmt.Fprintln(env.stderr, "error: --log and --output (or --inventory) are required")
		return 2
	}

	provider, model, err := newAIProvider(af, env.getenv, env.client)
	if err != nil {
		fmt.Fprintf(env.stderr, "error: %v\n", err)
		return 2
	}

	logText, err := readLog(*logPath, env.stdin)
	if err != nil {
		fmt.Fprintf(env.stderr, "error: read log: %v\n", err)
		return 2
	}
	invPath := *inventoryPath
	if invPath == "" {
		invPath = filepath.Join(*outputDir, hardener.InventoryFilename)
	}
	entries, err := loadInventoryFile(invPath)
	if err != nil {
		fmt.Fprintf(env.stderr, "error: %v\n", err)
		return 2
	}

	redacted := ai.Redact(logText)
	cands := candidates.Generate(entries, redacted, candidates.Options{Max: diagnoseMaxCandidates})

	out := diagnoseOutput{Suggestions: []diagnoseSuggestion{}, Candidates: len(cands)}
	var selectable []candidates.Candidate
	for _, c := range cands {
		if c.Match == candidates.MatchQuoted || c.Match == candidates.MatchBasename {
			out.Suggestions = append(out.Suggestions, diagnoseSuggestion{
				Path: c.Path, Source: "deterministic", Match: c.Match, Evidence: c.Evidence})
		} else {
			selectable = append(selectable, c)
		}
	}

	if provider != nil && len(selectable) > 0 {
		picks, resp, err := selectCandidates(context.Background(), provider, redacted, selectable)
		if err != nil {
			out.Note = "model suggestions unavailable: " + aiErrorNote(err)
		} else {
			out.Model = aiLabel(resp, model)
			byPath := map[string]candidates.Candidate{}
			for _, c := range selectable {
				byPath[c.Path] = c
			}
			for _, p := range picks {
				c := byPath[p]
				out.Suggestions = append(out.Suggestions, diagnoseSuggestion{
					Path: c.Path, Source: "model", Match: c.Match, Evidence: c.Evidence})
			}
		}
	} else if provider == nil && len(selectable) > 0 && len(out.Suggestions) == 0 {
		out.Note = fmt.Sprintf("%d weaker matches were not ranked; configure a model (see docs/ai.md) to pick among them", len(selectable))
	}

	out.Suggestions = dropCovered(out.Suggestions)
	if len(out.Suggestions) > 0 {
		emptyDirs := emptySourceDirs(entries)
		var b strings.Builder
		b.WriteString("harden build ...")
		for i, s := range out.Suggestions {
			out.Suggestions[i].Flag = "--include"
			if emptyDirs[s.Path] {
				out.Suggestions[i].Flag = "--mkdir"
			}
			b.WriteString(" " + out.Suggestions[i].Flag + " " + s.Path)
		}
		out.Rerun = b.String()
	}

	if *asJSON {
		enc := json.NewEncoder(env.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(env.stderr, "error: %v\n", err)
			return 1
		}
		return 0
	}
	printDiagnose(env.stdout, out)
	return 0
}

// dropCovered removes suggestions that lie beneath another suggested path:
// --include of a directory already restores everything under it.
func dropCovered(sugs []diagnoseSuggestion) []diagnoseSuggestion {
	picked := make(map[string]bool, len(sugs))
	for _, s := range sugs {
		picked[s.Path] = true
	}
	out := sugs[:0]
	for _, s := range sugs {
		covered := false
		for d := path.Dir(s.Path); d != "/" && d != "."; d = path.Dir(d) {
			if picked[d] {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, s)
		}
	}
	return out
}

// emptySourceDirs returns the source directories that have no file, symlink
// or other non-directory entry anywhere beneath them.
func emptySourceDirs(entries []candidates.Entry) map[string]bool {
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.InSource && e.Type == hardener.InventoryTypeDir {
			dirs[e.Path] = true
		}
	}
	for _, e := range entries {
		if !e.InSource || e.Type == hardener.InventoryTypeDir {
			continue
		}
		for d := path.Dir(e.Path); d != "/" && d != "."; d = path.Dir(d) {
			delete(dirs, d)
		}
	}
	return dirs
}

// aiErrorNote describes a failed model call without echoing the model's
// answer, which may name paths that are not candidates.
func aiErrorNote(err error) string {
	switch {
	case errors.Is(err, ai.ErrInvalidOutput):
		return "the answer was rejected (not valid JSON, or it picked paths outside the candidate list)"
	case errors.Is(err, ai.ErrRefused):
		return "the model refused to answer"
	case errors.Is(err, ai.ErrTruncated):
		return "the answer was truncated"
	}
	return err.Error()
}

func printDiagnose(w io.Writer, out diagnoseOutput) {
	if len(out.Suggestions) == 0 {
		fmt.Fprintln(w, diagnoseNothingFound)
		if out.Note != "" {
			fmt.Fprintf(w, "Note: %s\n", out.Note)
		}
		return
	}
	width := 0
	for _, s := range out.Suggestions {
		width = max(width, len(s.Path))
	}
	for _, s := range out.Suggestions {
		if s.Source == "deterministic" {
			fmt.Fprintf(w, "Likely missing (from log):  %-*s  [deterministic]\n", width, s.Path)
			continue
		}
		ev := s.Evidence
		if len(ev) > 100 {
			ev = ev[:100] + "..."
		}
		fmt.Fprintf(w, "Suggested by model (%s):  %-*s  — %q\n", out.Model, width, s.Path, ev)
	}
	if out.Note != "" {
		fmt.Fprintf(w, "Note: %s\n", out.Note)
	}
	fmt.Fprintf(w, "Re-run with:\n  %s\n", out.Rerun)
}

// readLog reads a log file (or stdin for "-") and middle-truncates it to
// diagnoseMaxLogBytes.
func readLog(p string, stdin io.Reader) (string, error) {
	var r io.Reader
	if p == "-" {
		r = stdin
	} else {
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	// Keep head and tail when truncating: errors show up at both ends of a log.
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return ai.TruncateMiddle(string(data), diagnoseMaxLogBytes), nil
}

func loadInventoryFile(p string) ([]candidates.Entry, error) {
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("inventory.json not found (%s); re-run harden build with a version that writes it", p)
		}
		return nil, err
	}
	defer f.Close()
	entries, err := candidates.LoadInventory(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return entries, nil
}

const diagnoseSystemPrompt = `A hardened container image (the source image minus every file that was not observed at runtime) fails at startup.
You receive the container log and a numbered list of candidate paths. Each candidate exists in the source image and was removed from the hardened image, and the log refers to it in some way.
Pick the candidates whose absence most likely causes the failure, at most 10, most likely first. Only pick paths from the list, copied exactly. Prefer the smallest set that explains the error. When a missing module or package is a directory in the list, pick the directory rather than files inside it: including a directory restores everything beneath it.
If the failure looks environmental (network, credentials, configuration, permissions) or no candidate fits, return an empty list.`

var selectSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "paths": {"type": "array", "items": {"type": "string"}, "maxItems": 10}
  },
  "required": ["paths"],
  "additionalProperties": false
}`)

type selectAnswer struct {
	Paths []string `json:"paths"`
}

// selectCandidates asks the model to pick among cands. The answer is accepted
// only if every pick is one of cands, with no repeats, and there are at most
// diagnoseMaxPicks. The provider redacts the prompt; logText and the evidence
// lines are already redacted.
func selectCandidates(ctx context.Context, p ai.Provider, logText string, cands []candidates.Candidate) ([]string, ai.Response, error) {
	if len(cands) > diagnosePromptCands {
		cands = cands[:diagnosePromptCands]
	}
	allowed := make(map[string]bool, len(cands))
	var b strings.Builder
	b.WriteString("Container log (excerpt):\n")
	b.WriteString(ai.TruncateMiddle(logText, diagnosePromptLogBytes))
	b.WriteString("\n\nCandidates (path, match kind, matching log line):\n")
	for i, c := range cands {
		allowed[c.Path] = true
		fmt.Fprintf(&b, "%d. %s  [%s]  %s\n", i+1, c.Path, c.Match, c.Evidence)
	}
	b.WriteString("\nAnswer with JSON: {\"paths\": [...]}.")

	validate := func(a selectAnswer) error {
		if len(a.Paths) > diagnoseMaxPicks {
			return fmt.Errorf("%d paths, at most %d allowed", len(a.Paths), diagnoseMaxPicks)
		}
		seen := map[string]bool{}
		for _, p := range a.Paths {
			if !allowed[p] {
				return fmt.Errorf("%q is not one of the candidates", p)
			}
			if seen[p] {
				return fmt.Errorf("%q is listed twice", p)
			}
			seen[p] = true
		}
		return nil
	}
	ans, resp, err := ai.CompleteJSON(ctx, p, ai.Request{
		Tier:       ai.TierFast,
		System:     diagnoseSystemPrompt,
		Messages:   []ai.Message{{Role: "user", Text: b.String()}},
		Schema:     selectSchema,
		SchemaName: "selection",
		MaxTokens:  aiMaxTokens,
	}, validate)
	if err != nil {
		return nil, resp, err
	}
	return ans.Paths, resp, nil
}
