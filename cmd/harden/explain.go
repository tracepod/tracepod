package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tracepod/tracepod/ai"
	"github.com/tracepod/tracepod/ai/candidates"
	"github.com/tracepod/tracepod/hardener"
	"github.com/tracepod/tracepod/manifest"
)

// cmdEnv carries the process environment so tests can run the subcommands
// without touching the real environment, stdin, or the network.
type cmdEnv struct {
	getenv func(string) string
	client *http.Client
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func osCmdEnv() cmdEnv {
	return cmdEnv{getenv: os.Getenv, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
}

// explainTopPackages is how many removed packages explain lists.
const explainTopPackages = 15

// explainMaxWords caps the model's prose.
const explainMaxWords = 150

// explainSummary is the deterministic part of `harden explain`.
type explainSummary struct {
	Inventory       bool              `json:"inventory"`
	SourcePaths     int               `json:"source_paths,omitempty"`
	HardenedPaths   int               `json:"hardened_paths,omitempty"`
	KeptPaths       int               `json:"kept_paths,omitempty"`
	AddedPaths      int               `json:"added_paths,omitempty"`
	RemovedPaths    int               `json:"removed_paths"`
	RemovedPackages int               `json:"removed_packages"`
	TopPackages     []explainPackage  `json:"top_removed_packages"`
	Categories      []explainCategory `json:"categories"`
	KeptBySource    map[string]int    `json:"kept_by_source,omitempty"`
}

type explainPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl"`
	Paths   int    `json:"paths"`
}

type explainCategory struct {
	Name     string   `json:"name"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
}

type explainOutput struct {
	Deterministic explainSummary `json:"deterministic"`
	Prose         string         `json:"prose,omitempty"`
	Model         string         `json:"model,omitempty"`
	Note          string         `json:"note,omitempty"`
}

func runExplain(args []string) int { return runExplainWith(args, osCmdEnv()) }

func runExplainWith(args []string, env cmdEnv) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var (
		outputDir     = fs.String("output", "", "Output directory of a previous `harden build` (required)")
		inventoryPath = fs.String("inventory", "", "Path to inventory.json if the build used --inventory-out (default: <output>/inventory.json)")
		manifestPath  = fs.String("manifest", "", "Sensor manifest used for the build; adds kept-path counts by observation source")
		asJSON        = fs.Bool("json", false, "Print JSON instead of text")
		af            aiFlags
	)
	af.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.stderr, "Usage: harden explain --output <dir> [--manifest <file>] [--json] [--no-ai]")
		fmt.Fprintln(env.stderr, "\nSummarise what a build removed and kept. A model, if configured, adds a short plain-English summary.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *outputDir == "" {
		fs.Usage()
		fmt.Fprintln(env.stderr, "error: --output is required")
		return 2
	}

	provider, model, err := newAIProvider(af, env.getenv, env.client)
	if err != nil {
		fmt.Fprintf(env.stderr, "error: %v\n", err)
		return 2
	}

	rm, err := readRemovalManifest(filepath.Join(*outputDir, hardener.RemovalManifestFilename))
	if err != nil {
		fmt.Fprintf(env.stderr, "error: %v\n", err)
		return 2
	}
	invPath := *inventoryPath
	if invPath == "" {
		invPath = filepath.Join(*outputDir, hardener.InventoryFilename)
	}
	var entries []candidates.Entry
	if f, err := os.Open(invPath); err == nil {
		entries, err = candidates.LoadInventory(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(env.stderr, "error: %s: %v\n", invPath, err)
			return 2
		}
	} else if *inventoryPath != "" || !os.IsNotExist(err) {
		fmt.Fprintf(env.stderr, "error: %v\n", err)
		return 2
	}
	var m *manifest.Manifest
	if *manifestPath != "" {
		if m, err = loadManifest(*manifestPath); err != nil {
			fmt.Fprintf(env.stderr, "error: load manifest %s: %v\n", *manifestPath, err)
			return 2
		}
	}

	sum := summarizeBuild(rm, entries, m)
	text := renderExplain(sum)
	out := explainOutput{Deterministic: sum}
	if provider != nil {
		prose, resp, err := explainProse(context.Background(), provider, text)
		switch {
		case err != nil:
			out.Note = "model summary unavailable: " + aiErrorNote(err)
		default:
			out.Prose, out.Model = prose, aiLabel(resp, model)
		}
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
	fmt.Fprint(env.stdout, text)
	if out.Prose != "" {
		fmt.Fprintf(env.stdout, "\nSummary (model: %s):\n%s\n", out.Model, wrapText(out.Prose, 78, "  "))
	}
	if out.Note != "" {
		fmt.Fprintf(env.stdout, "\nNote: %s\n", out.Note)
	}
	return 0
}

func aiLabel(resp ai.Response, configured string) string {
	if resp.Model != "" {
		return resp.Model
	}
	return configured
}

func readRemovalManifest(p string) (*hardener.RemovalManifest, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found; run harden explain on the --output directory of a successful harden build", p)
		}
		return nil, err
	}
	var rm hardener.RemovalManifest
	if err := json.Unmarshal(data, &rm); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &rm, nil
}

// summarizeBuild computes the deterministic explain block. entries and m are
// optional.
func summarizeBuild(rm *hardener.RemovalManifest, entries []candidates.Entry, m *manifest.Manifest) explainSummary {
	s := explainSummary{
		Inventory:       len(entries) > 0,
		RemovedPackages: len(rm.Removed),
		TopPackages:     []explainPackage{},
		Categories:      []explainCategory{},
	}

	// Removed paths: from the inventory when present (it covers files no
	// package owns), otherwise the union of the removed packages' paths.
	removed := map[string]bool{} // path -> is a directory
	if s.Inventory {
		for _, e := range entries {
			switch {
			case e.InSource && e.InHardened:
				s.SourcePaths++
				s.HardenedPaths++
				s.KeptPaths++
			case e.InSource:
				s.SourcePaths++
				removed[e.Path] = e.Type == hardener.InventoryTypeDir
			case e.InHardened:
				s.HardenedPaths++
				s.AddedPaths++
			}
		}
	} else {
		for _, p := range rm.Removed {
			for _, path := range p.Paths {
				removed[path] = false
			}
		}
	}
	s.RemovedPaths = len(removed)

	pkgs := make([]explainPackage, 0, len(rm.Removed))
	for _, p := range rm.Removed {
		name := p.Name
		if name == "" {
			name = p.Purl
		}
		pkgs = append(pkgs, explainPackage{Name: name, Version: p.Version, Purl: p.Purl, Paths: len(p.Paths)})
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Paths != pkgs[j].Paths {
			return pkgs[i].Paths > pkgs[j].Paths
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Purl < pkgs[j].Purl
	})
	if len(pkgs) > explainTopPackages {
		pkgs = pkgs[:explainTopPackages]
	}
	s.TopPackages = pkgs

	byCat := map[string][]string{}
	for p, isDir := range removed {
		if isDir {
			continue
		}
		if c := pathCategory(p); c != "" {
			byCat[c] = append(byCat[c], p)
		}
	}
	for _, c := range categoryOrder {
		ps := byCat[c]
		if len(ps) == 0 {
			continue
		}
		sort.Strings(ps)
		ex := ps
		if len(ex) > 3 {
			ex = ex[:3]
		}
		s.Categories = append(s.Categories, explainCategory{Name: c, Count: len(ps), Examples: ex})
	}

	if m != nil {
		s.KeptBySource = map[string]int{}
		for _, e := range m.Files {
			src := string(e.Source)
			if src == "" {
				src = "unknown"
			}
			s.KeptBySource[src]++
		}
	}
	return s
}

// Removed-path categories, in display order.
const (
	catShells   = "shells"
	catPkgMgrs  = "package managers"
	catNetTools = "network tools"
	catDocs     = "docs and man pages"
	catTests    = "test directories"
	catLocale   = "locale data"
)

var categoryOrder = []string{catShells, catPkgMgrs, catNetTools, catDocs, catTests, catLocale}

var (
	binDirs = map[string]bool{"/bin": true, "/sbin": true, "/usr/bin": true, "/usr/sbin": true,
		"/usr/local/bin": true, "/usr/local/sbin": true}
	shellNames = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true,
		"ksh": true, "mksh": true, "csh": true, "tcsh": true, "fish": true, "rbash": true}
	pkgMgrNames = map[string]bool{"apt": true, "apt-get": true, "apt-cache": true, "apt-config": true,
		"apt-key": true, "apt-mark": true, "dpkg": true, "dpkg-deb": true, "dpkg-query": true,
		"dpkg-divert": true, "dpkg-split": true, "dpkg-trigger": true, "dpkg-statoverride": true,
		"dpkg-maintscript-helper": true, "dpkg-realpath": true, "apk": true, "pip": true,
		"easy_install": true, "yum": true, "dnf": true, "microdnf": true, "rpm": true}
	pkgMgrPrefixes = []string{"/var/lib/dpkg/", "/var/lib/apt/", "/var/cache/apt/", "/etc/apt/",
		"/etc/dpkg/", "/usr/share/dpkg/", "/lib/apk/", "/etc/apk/", "/usr/lib/apk/", "/var/cache/apk/",
		"/var/lib/rpm/", "/usr/lib/apt/"}
	pipVersioned = regexp.MustCompile(`^pip\d+(\.\d+)?$`)
	pipPackage   = regexp.MustCompile(`/(site|dist)-packages/pip[-/]`)
	netToolNames = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
		"telnet": true, "ftp": true, "ssh": true, "scp": true, "sftp": true, "socat": true,
		"nslookup": true, "dig": true, "ping": true, "traceroute": true}
	docPrefixes    = []string{"/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/local/share/doc/", "/usr/local/share/man/"}
	localePrefixes = []string{"/usr/share/locale/", "/usr/lib/locale/", "/usr/share/i18n/", "/usr/local/share/locale/"}
)

// pathCategory classifies a removed path by path heuristics, or returns "".
func pathCategory(p string) string {
	dir, base := path.Split(p)
	inBin := binDirs[strings.TrimSuffix(dir, "/")]
	switch {
	case inBin && shellNames[base]:
		return catShells
	case inBin && (pkgMgrNames[base] || pipVersioned.MatchString(base)),
		hasAnyPrefix(p, pkgMgrPrefixes), pipPackage.MatchString(p):
		return catPkgMgrs
	case inBin && netToolNames[base]:
		return catNetTools
	case hasAnyPrefix(p, docPrefixes):
		return catDocs
	case strings.Contains(p, "/test/") || strings.Contains(p, "/tests/"):
		return catTests
	case hasAnyPrefix(p, localePrefixes):
		return catLocale
	}
	return ""
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// renderExplain prints the deterministic block. Its text is also the only
// input the model sees.
func renderExplain(s explainSummary) string {
	var b strings.Builder
	b.WriteString("Build summary\n")
	if s.Inventory {
		fmt.Fprintf(&b, "  Source image:      %d paths\n", s.SourcePaths)
		fmt.Fprintf(&b, "  Hardened image:    %d paths (%d kept from the source, %d added)\n", s.HardenedPaths, s.KeptPaths, s.AddedPaths)
		fmt.Fprintf(&b, "  Removed:           %d paths\n", s.RemovedPaths)
	} else {
		fmt.Fprintf(&b, "  Removed:           %d paths owned by removed packages (no inventory.json; path counts are partial)\n", s.RemovedPaths)
	}
	fmt.Fprintf(&b, "  Removed packages:  %d\n", s.RemovedPackages)

	if len(s.TopPackages) > 0 {
		fmt.Fprintf(&b, "\nLargest removed packages (by path count):\n")
		w := 0
		for _, p := range s.TopPackages {
			w = max(w, len(pkgLabel(p)))
		}
		for _, p := range s.TopPackages {
			fmt.Fprintf(&b, "  %-*s  %d %s\n", w, pkgLabel(p), p.Paths, pluralStr(p.Paths, "path", "paths"))
		}
	}

	if len(s.Categories) > 0 {
		fmt.Fprintf(&b, "\nRemoved by category (files and links):\n")
		for _, c := range s.Categories {
			more := ""
			if c.Count > len(c.Examples) {
				more = ", ..."
			}
			fmt.Fprintf(&b, "  %-20s %5d  %s%s\n", c.Name, c.Count, strings.Join(c.Examples, ", "), more)
		}
	}

	if s.KeptBySource != nil {
		fmt.Fprintf(&b, "\nKept paths by observation source (from --manifest):\n")
		keys := make([]string, 0, len(s.KeptBySource))
		for k := range s.KeptBySource {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-20s %5d\n", k, s.KeptBySource[k])
		}
	}
	return b.String()
}

func pkgLabel(p explainPackage) string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + " " + p.Version
}

const explainSystemPrompt = `You summarise container image hardening results for a reviewer who must approve the hardened image.
You receive a factual summary of what a build removed from the source image and what it kept.
Write at most 120 words of plain English prose: what was removed, why that reduces attack surface, and anything a reviewer should double-check.
Use only facts from the summary. Do not invent paths, packages, versions or numbers. Do not use Markdown, lists or headings.`

// explainProse asks the model for a short summary of text and checks that
// every path and quoted name in the answer appears in text.
func explainProse(ctx context.Context, p ai.Provider, text string) (string, ai.Response, error) {
	resp, err := p.Complete(ctx, ai.Request{
		Tier:      ai.TierFast,
		System:    explainSystemPrompt,
		Messages:  []ai.Message{{Role: "user", Text: text}},
		MaxTokens: aiMaxTokens,
	})
	if err != nil {
		return "", resp, err
	}
	prose := strings.Join(strings.Fields(resp.Text), " ")
	if prose == "" {
		return "", resp, errors.New("empty answer")
	}
	if err := checkProse(prose, text); err != nil {
		return "", resp, fmt.Errorf("answer dropped: %v", err)
	}
	return prose, resp, nil
}

var (
	proseAbsPath = regexp.MustCompile(`/[A-Za-z0-9._+@-]+(?:/[A-Za-z0-9._+@-]*)*`)
	proseQuoted  = regexp.MustCompile("`([^`]+)`|\"([^\"]+)\"")
)

// checkProse rejects prose that names a path, or a quoted or backticked token,
// that the input does not contain, or that is too long.
func checkProse(prose, input string) error {
	if n := len(strings.Fields(prose)); n > explainMaxWords {
		return fmt.Errorf("%d words, limit %d", n, explainMaxWords)
	}
	for _, m := range proseAbsPath.FindAllStringIndex(prose, -1) {
		// Only tokens that start a word: "and/or" and "1/2" are not paths.
		if m[0] > 0 && !strings.ContainsRune(" (\"'`", rune(prose[m[0]-1])) {
			continue
		}
		tok := strings.TrimRight(prose[m[0]:m[1]], ".,;:")
		if len(tok) > 1 && !strings.Contains(input, tok) {
			return fmt.Errorf("names %q, which is not in the summary", tok)
		}
	}
	for _, m := range proseQuoted.FindAllStringSubmatch(prose, -1) {
		tok := strings.TrimSpace(m[1] + m[2])
		if tok != "" && !strings.Contains(input, tok) {
			return fmt.Errorf("quotes %q, which is not in the summary", tok)
		}
	}
	return nil
}

// wrapText wraps s at width columns with the given indent.
func wrapText(s string, width int, indent string) string {
	var b strings.Builder
	line := indent
	for _, w := range strings.Fields(s) {
		if len(line) > len(indent) && len(line)+1+len(w) > width {
			b.WriteString(line + "\n")
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += w
	}
	b.WriteString(line)
	return b.String()
}
