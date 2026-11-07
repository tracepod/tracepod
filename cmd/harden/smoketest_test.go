package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLastLines(t *testing.T) {
	if got := lastLines("a\nb\nc", 2); got != "b\nc" {
		t.Errorf("got %q", got)
	}
	if got := lastLines("a", 5); got != "a" {
		t.Errorf("got %q", got)
	}
}

func TestSaveSmokeLogKeepsTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), smokeLogFilename)
	big := strings.Repeat("x", smokeLogMaxBytes) + "the last line"
	saveSmokeLog(p, []byte(big))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != smokeLogMaxBytes || !strings.HasSuffix(string(data), "the last line") {
		t.Fatalf("len %d", len(data))
	}
	saveSmokeLog("", []byte("ignored")) // no path: no-op
}
