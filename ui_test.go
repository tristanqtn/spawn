package main

import (
	"strings"
	"testing"
)

// Colour codes must not affect column alignment, which is the whole reason the table
// measures visible width rather than len().
func TestVisibleWidthIgnoresColour(t *testing.T) {
	plain := "running"
	painted := "\x1b[32m" + plain + "\x1b[0m"
	if got := visibleWidth(painted); got != len(plain) {
		t.Errorf("visibleWidth(coloured) = %d, want %d", got, len(plain))
	}
	if visibleWidth("héllo") != 5 {
		t.Errorf("multibyte runes should count as one column each")
	}
}

func TestTableAligns(t *testing.T) {
	var b strings.Builder
	tb := newTable("NAME", "STATE")
	tb.add("a", "running")
	tb.add("much-longer-name", "exited")
	tb.render(&b)

	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header, rule and two rows, got %d lines:\n%s", len(lines), b.String())
	}
	// The rule spans the widest cell in each column.
	if !strings.HasPrefix(lines[1], strings.Repeat("-", len("much-longer-name"))) {
		t.Errorf("rule does not span the widest column: %q", lines[1])
	}
	// Every row's second column starts at the same offset.
	want := strings.Index(lines[0], "STATE")
	for _, l := range lines[2:] {
		if got := strings.Index(l, "running") + strings.Index(l, "exited") + 1; got != want {
			// One of the two indexes is -1, so the sum plus one is the real offset.
			t.Errorf("column 2 misaligned in %q (offset %d, want %d)", l, got, want)
		}
	}
	// No trailing whitespace: it shows up when output is pasted.
	for _, l := range lines {
		if l != strings.TrimRight(l, " ") {
			t.Errorf("trailing whitespace in %q", l)
		}
	}
}

// Piped output must stay machine-readable, so colour is off unless stdout is a TTY.
// Under `go test` it never is, which is what makes this assertion meaningful.
func TestNoColourWhenNotATerminal(t *testing.T) {
	if ui.green != "" || ui.bold != "" {
		t.Error("colour should be disabled when stdout is not a terminal")
	}
	if ui.paint(ui.green, "x") != "x" {
		t.Error("paint should be a no-op without a palette")
	}
}

func TestTruncateKeepsTheTail(t *testing.T) {
	// A manifest path's useful part is its end, so the front is what gets dropped.
	got := truncate("/home/someone/very/deep/tree/spawn.toml", 20)
	if len([]rune(got)) != 20 || !strings.HasSuffix(got, "spawn.toml") || !strings.HasPrefix(got, "...") {
		t.Errorf("truncate = %q", got)
	}
	if truncate("short", 20) != "short" {
		t.Error("a short string should be untouched")
	}
}

func TestBannerHasNoEmoji(t *testing.T) {
	// Emoji render inconsistently over SSH and in minimal fonts.
	for _, r := range bannerArt {
		if r > 0x2500 {
			t.Errorf("non-ASCII box or emoji rune %U in the banner", r)
		}
	}
}
