package main

// Terminal presentation: colour, tables and the banner. Deliberately hand-rolled
// rather than pulled in, because the whole of it is less code than wiring up a CLI
// framework, and spawn's output is three tables and a help screen.
//
// No emoji anywhere. They render inconsistently across terminals and fonts, and this
// is a tool people run over SSH into a box they just built.

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// ANSI attributes, emptied when the output is not an interactive terminal.
type palette struct{ reset, bold, dim, green, yellow, red, cyan string }

var ui = loadPalette()

func loadPalette() palette {
	if !colorOK() {
		return palette{}
	}
	return palette{
		reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
		green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m", cyan: "\x1b[36m",
	}
}

// colorOK follows the conventions users already expect: NO_COLOR wins, a dumb
// terminal gets nothing, and a redirected stdout gets nothing so piped output stays
// machine-readable.
func colorOK() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") != "" {
		return true
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (p palette) paint(attr, s string) string {
	if attr == "" {
		return s
	}
	return attr + s + p.reset
}

// table lays out aligned columns with a rule under the header. Cells may contain
// colour, so widths are measured on the visible text only.
type table struct {
	head []string
	rows [][]string
}

func newTable(head ...string) *table { return &table{head: head} }

func (t *table) add(cells ...string) { t.rows = append(t.rows, cells) }

// visibleWidth counts runes, ignoring ANSI escapes, so a coloured cell still aligns.
func visibleWidth(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			n++
		}
	}
	return n
}

func (t *table) render(w io.Writer) {
	cols := len(t.head)
	for _, r := range t.rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	width := make([]int, cols)
	measure := func(cells []string) {
		for i, c := range cells {
			if n := visibleWidth(c); n > width[i] {
				width[i] = n
			}
		}
	}
	measure(t.head)
	for _, r := range t.rows {
		measure(r)
	}

	const gap = "  "
	line := func(cells []string, paint string) {
		var b strings.Builder
		for i, c := range cells {
			if i > 0 {
				b.WriteString(gap)
			}
			pad := width[i] - visibleWidth(c)
			// The last column needs no trailing padding; it only adds noise when
			// the output is copied.
			if i == len(cells)-1 {
				b.WriteString(ui.paint(paint, c))
			} else {
				b.WriteString(ui.paint(paint, c) + strings.Repeat(" ", pad))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}

	if len(t.head) > 0 {
		line(t.head, ui.bold)
		rule := make([]string, cols)
		for i := range rule {
			rule[i] = strings.Repeat("-", width[i])
		}
		line(rule, ui.dim)
	}
	for _, r := range t.rows {
		line(r, "")
	}
}

func (t *table) print() { t.render(os.Stdout) }

// banner is shown on the help screen only. Printing art before every command would
// be noise in a tool that gets scripted.
const bannerArt = `   ___ _ __   __ ___      ___ __
  / __| '_ \ / _` + "`" + ` \ \ /\ / / '_ \
  \__ \ |_) | (_| |\ V  V /| | | |
  |___/ .__/ \__,_| \_/\_/ |_| |_|
      |_|`

func banner(w io.Writer) {
	fmt.Fprintln(w, ui.paint(ui.cyan, bannerArt))
	fmt.Fprintf(w, "  %s  %s\n\n",
		ui.paint(ui.bold, "declarative, disposable environments"),
		ui.paint(ui.dim, version))
}

// status renders a doctor result as a fixed-width, colour-coded marker. Words rather
// than symbols: this output gets pasted into issues, where symbols become mojibake.
func (r result) badge() string {
	switch r {
	case ok:
		return ui.paint(ui.green, "ok")
	case warn:
		return ui.paint(ui.yellow, "warn")
	}
	return ui.paint(ui.red, "FAIL")
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return "..." + string(r[len(r)-(max-3):])
}
