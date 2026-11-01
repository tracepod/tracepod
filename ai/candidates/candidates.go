// Package candidates deterministically derives the set of file paths a model
// may choose from when a hardened image fails at runtime. Candidates come only
// from the build's file inventory (paths that exist in the source image but
// were left out of the hardened image) and are ranked by how directly the
// workload's log output refers to them. The package is pure Go and never calls
// a model: a model, if one is used at all, can only select among the results.
package candidates

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Entry mirrors one element of the "files" array of an inventory document.
type Entry struct {
	Path       string `json:"path"`
	Type       string `json:"type,omitempty"` // file | dir | symlink | other; empty when not in the source image
	LinkTarget string `json:"link_target,omitempty"`
	InHardened bool   `json:"in_hardened"`
	// InSource is false for paths that exist only in the hardened image
	// (version 2 documents). LoadInventory sets it for version 1 documents,
	// which list source paths only.
	InSource bool `json:"in_source"`
}

// InventoryVersion is the newest supported document version. Versions
// 1..InventoryVersion are accepted.
const InventoryVersion = 2

// LoadInventory decodes {"version":N,"files":[...]} for N in
// 1..InventoryVersion. Other versions are an error.
func LoadInventory(r io.Reader) ([]Entry, error) {
	var doc struct {
		Version int     `json:"version"`
		Files   []Entry `json:"files"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding inventory: %w", err)
	}
	if doc.Version < 1 || doc.Version > InventoryVersion {
		return nil, fmt.Errorf("unsupported inventory version %d (supported: 1..%d)", doc.Version, InventoryVersion)
	}
	if doc.Version == 1 {
		for i := range doc.Files {
			doc.Files[i].InSource = true
		}
	}
	return doc.Files, nil
}

// Match kinds, strongest first.
const (
	MatchQuoted   = "quoted"
	MatchBasename = "basename"
	MatchSegment  = "segment"
	MatchStem     = "stem"
)

var matchScore = map[string]int{MatchQuoted: 100, MatchBasename: 80, MatchSegment: 60, MatchStem: 40}

// Candidate is a path the model may select.
type Candidate struct {
	Path  string `json:"path"`
	Score int    `json:"score"`
	Match string `json:"match"`
	// Evidence is the log line that produced the matching token. It is raw log
	// text: callers must redact it before sending it anywhere.
	Evidence string `json:"evidence"`
}

// Options tunes Generate.
type Options struct {
	// Max caps the result length. Default 200.
	Max int
}

const (
	defaultMax     = 200
	maxErrorLines  = 500
	maxEvidenceLen = 300
	maxLinkHops    = 8
)

var (
	errorLine    = regexp.MustCompile(`(?i)error|exception|not found|no module|cannot|failed|undefined symbol|no such file`)
	quotedPath   = regexp.MustCompile(`["'](/[^"']+)["']`)
	dottedName   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+`)
	libName      = regexp.MustCompile(`lib[\w.+-]*\.so[\d.]*`)
	wordToken    = regexp.MustCompile(`[A-Za-z0-9_][\w.+-]*`)
	excludedPfx  = []string{"/proc/", "/sys/", "/dev/"}
	genericWords = map[string]bool{
		"error": true, "errors": true, "exception": true, "failed": true, "failure": true, "cannot": true,
		"not": true, "found": true, "the": true, "and": true, "for": true, "with": true, "file": true,
		"files": true, "directory": true, "module": true, "named": true, "import": true, "open": true,
		"opening": true, "load": true, "loading": true, "such": true, "unable": true, "could": true,
		"can't": true, "undefined": true, "symbol": true, "shared": true, "object": true, "library": true,
		"libraries": true, "while": true, "from": true, "line": true, "traceback": true, "most": true,
		"recent": true, "call": true, "last": true, "fatal": true, "warn": true, "warning": true,
		"info": true, "panic": true, "java": true, "lang": true, "node": true, "main": true,
		"permission": true, "denied": true, "connection": true, "refused": true, "timeout": true,
		"timed": true, "out": true, "true": true, "false": true, "null": true, "none": true,
	}
)

type tokenInfo struct {
	evidence string
	order    int
}

// Generate returns up to opt.Max candidates, sorted by score descending then
// path ascending. It is deterministic: equal inputs give equal output.
//
// The universe is every inventory entry that is absent from the hardened image
// (InHardened == false) and not under /proc, /sys or /dev. Log lines that look
// like errors yield tokens (quoted absolute paths, dotted module names, shared
// library names, Java class names and plain words of three or more bytes), which
// are matched to universe paths by, in order of strength, exact quoted path,
// basename, multi-component path segment sequence (a.b.c matches .../a/b/c) and
// basename stem. A matched symlink also nominates its target when the target is
// in the universe, one point lower per hop.
func Generate(entries []Entry, logs string, opt Options) []Candidate {
	if opt.Max <= 0 {
		opt.Max = defaultMax
	}
	universe := make(map[string]Entry)
	for _, e := range entries {
		if e.InHardened || !strings.HasPrefix(e.Path, "/") || excluded(e.Path) {
			continue
		}
		universe[e.Path] = e
	}
	if len(universe) == 0 {
		return nil
	}

	quoted := map[string]tokenInfo{} // absolute path -> evidence
	plain := map[string]tokenInfo{}  // basename / stem tokens
	multi := map[string]tokenInfo{}  // a/b/c tokens
	order := 0
	lines := 0
	for _, raw := range strings.Split(logs, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !errorLine.MatchString(line) {
			continue
		}
		if lines++; lines > maxErrorLines {
			break
		}
		ev := line
		if len(ev) > maxEvidenceLen {
			ev = ev[:maxEvidenceLen]
		}
		add := func(m map[string]tokenInfo, tok string) {
			if tok == "" {
				return
			}
			if _, ok := m[tok]; !ok {
				order++
				m[tok] = tokenInfo{evidence: ev, order: order}
			}
		}
		for _, m := range quotedPath.FindAllStringSubmatch(line, -1) {
			p := path.Clean(m[1])
			add(quoted, p)
			if b := path.Base(p); len(b) >= 3 {
				add(plain, b)
			}
		}
		for _, d := range dottedName.FindAllString(line, -1) {
			parts := strings.Split(d, ".")
			add(multi, strings.Join(parts, "/"))
			if len(parts) >= 3 && isJavaPackage(parts) {
				add(multi, strings.Join(parts, "/")+".class")
			}
		}
		for _, l := range libName.FindAllString(line, -1) {
			add(plain, strings.TrimRight(l, "."))
		}
		for _, w := range wordToken.FindAllString(line, -1) {
			w = strings.TrimRight(w, ".+-")
			if len(w) < 3 || genericWords[strings.ToLower(w)] {
				continue
			}
			add(plain, w)
		}
	}

	best := map[string]Candidate{}
	offer := func(p string, c Candidate) {
		if cur, ok := best[p]; !ok || c.Score > cur.Score {
			best[p] = c
		}
	}
	paths := make([]string, 0, len(universe))
	for p := range universe {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	multiToks := make([]string, 0, len(multi))
	for t := range multi {
		multiToks = append(multiToks, t)
	}
	sort.Strings(multiToks)

	for _, p := range paths {
		var c Candidate
		switch {
		case has(quoted, p):
			c = Candidate{Path: p, Match: MatchQuoted, Evidence: quoted[p].evidence}
		case has(plain, path.Base(p)):
			c = Candidate{Path: p, Match: MatchBasename, Evidence: plain[path.Base(p)].evidence}
		default:
			if tok, ok := segmentMatch(p, multiToks); ok {
				c = Candidate{Path: p, Match: MatchSegment, Evidence: multi[tok].evidence}
			} else if tok, ok := stemMatch(path.Base(p), plain); ok {
				c = Candidate{Path: p, Match: MatchStem, Evidence: plain[tok].evidence}
			} else {
				continue
			}
		}
		c.Score = matchScore[c.Match]
		offer(p, c)
		// Follow symlinks to their targets.
		cur, score := universe[p], c.Score
		for hop := 0; hop < maxLinkHops && cur.Type == "symlink" && cur.LinkTarget != ""; hop++ {
			target := cur.LinkTarget
			if !strings.HasPrefix(target, "/") {
				target = path.Join(path.Dir(cur.Path), target)
			}
			target = path.Clean(target)
			next, ok := universe[target]
			if !ok {
				break
			}
			score--
			offer(target, Candidate{Path: target, Score: score, Match: c.Match, Evidence: c.Evidence})
			cur = next
		}
	}

	out := make([]Candidate, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > opt.Max {
		out = out[:opt.Max]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func has(m map[string]tokenInfo, k string) bool { _, ok := m[k]; return ok }

func excluded(p string) bool {
	for _, pre := range excludedPfx {
		if strings.HasPrefix(p, pre) || p == strings.TrimSuffix(pre, "/") {
			return true
		}
	}
	return false
}

// isJavaPackage reports whether a dotted name looks like a Java class name:
// lower-case package components followed by a capitalised final component.
func isJavaPackage(parts []string) bool {
	last := parts[len(parts)-1]
	if last == "" || last[0] < 'A' || last[0] > 'Z' {
		return false
	}
	return parts[0] != "" && parts[0][0] >= 'a' && parts[0][0] <= 'z'
}

// segmentMatch reports whether p contains tok (a/b/c) as a whole-segment
// sequence, either directly, as a source or package form of a module (tok plus
// an extension, or tok/__init__.*), or as a suffix for Java .class tokens.
func segmentMatch(p string, toks []string) (string, bool) {
	wrapped := p + "/"
	noExt := strings.TrimSuffix(p, path.Ext(p))
	for _, t := range toks {
		if strings.Contains(wrapped, "/"+t+"/") ||
			strings.HasSuffix(noExt, "/"+t) ||
			strings.Contains(noExt, "/"+t+"/__init__") {
			return t, true
		}
	}
	return "", false
}

// stemMatch matches a token against the basename without its extension, both
// trimming only the last extension and everything after the first dot.
func stemMatch(base string, plain map[string]tokenInfo) (string, bool) {
	if strings.HasPrefix(base, ".") {
		return "", false
	}
	if s := strings.TrimSuffix(base, path.Ext(base)); s != base && has(plain, s) {
		return s, true
	}
	if i := strings.IndexByte(base, '.'); i > 0 && has(plain, base[:i]) {
		return base[:i], true
	}
	return "", false
}
