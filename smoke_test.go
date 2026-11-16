package main

import (
	"os"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// Composition is the M5 feature that could silently do nothing: a profile that
// includes another and gets no tools from it would look fine until a tool was missing
// mid-engagement.
func TestProfileIncludesCompose(t *testing.T) {
	ad, err := profileTools("active-directory")
	if err != nil {
		t.Fatal(err)
	}
	// active-directory includes recon and creds, so nmap and hashcat have to be there
	// although the file itself lists neither.
	for _, want := range []string{"nmap", "hashcat", "netexec"} {
		if !contains(ad, want) {
			t.Errorf("active-directory should resolve %q through its includes", want)
		}
	}
	// And the file genuinely does not list them itself, or this test proves nothing.
	raw, err := profileFS.ReadFile("profiles/active-directory.toml")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	tools := body[strings.Index(body, "tools = ["):]
	if strings.Contains(tools, "\"nmap\"") {
		t.Error("active-directory lists nmap directly, so the include proves nothing")
	}
}

// The umbrella suite is the deliverable. It has to pull in every building block, and
// a diamond -- pentest includes both web and active-directory, which both include
// recon -- must dedup rather than repeat.
func TestPentestComposesWithoutDuplicates(t *testing.T) {
	tools, err := profileTools("pentest")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"nmap",       // recon
		"hashcat",    // creds
		"chisel",     // pivot
		"netexec",    // active-directory
		"ffuf",       // web
		"fzf",        // general
		"metasploit", // its own
	} {
		if !contains(tools, want) {
			t.Errorf("pentest is missing %q", want)
		}
	}
	// recon is reached twice, through web and through active-directory.
	seen := map[string]int{}
	for _, tool := range tools {
		seen[tool]++
	}
	if seen["nmap"] != 1 {
		t.Errorf("nmap appears %d times: the diamond is not deduplicated", seen["nmap"])
	}
	// A manifest naming it must still resolve to a deduplicated list.
	m, err := Parse([]byte("schema = 1\nname = \"p\"\nprofiles = [\"pentest\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, tool := range m.resolved {
		counts[tool]++
		if counts[tool] > 1 {
			t.Errorf("resolved list repeats %q", tool)
		}
	}
	if len(m.resolved) < 100 {
		t.Errorf("pentest resolved to only %d packages", len(m.resolved))
	}
}

// A cycle in includes must not hang or blow the stack. There is none in the shipped
// suites, so this drives profileToolsSeen directly with a pre-seeded set, which is
// the same state a cycle produces.
func TestProfileIncludeCycleTerminates(t *testing.T) {
	seen := map[string]bool{"recon": true}
	// web includes recon, which is already seen: it must come back with web's own
	// tools and no recursion into recon.
	got, err := profileToolsSeen("web", seen)
	if err != nil {
		t.Fatal(err)
	}
	if contains(got, "nmap") {
		t.Error("an already-visited include was expanded again")
	}
	if !contains(got, "ffuf") {
		t.Error("the suite's own tools went missing")
	}
	// And a self-include terminates rather than recursing forever.
	if _, err := profileToolsSeen("web", map[string]bool{"web": true}); err != nil {
		t.Fatal(err)
	}
}

// An include naming a suite that does not exist must say so, and say it at parse time
// rather than during a build.
func TestProfileIncludeMustExist(t *testing.T) {
	if _, err := profileToolsSeen("nope-not-a-suite", map[string]bool{}); err == nil {
		t.Fatal("a missing suite should be an error")
	}
	// A path separator in an include is the injection shape: it must be refused
	// before it reaches the embedded FS.
	if _, err := profileToolsSeen("../../etc/passwd", map[string]bool{}); err == nil {
		t.Error("an include with path separators should be refused")
	}
}

// The exit criterion: EVERY tool in a suite has a smoke check. This asserts the
// property rather than trusting the tables, which is the only version worth having --
// a tool added to a profile and forgotten in [smoke] still gets the default.
func TestEverySuiteToolHasASmokeCheck(t *testing.T) {
	for _, p := range profileNames() {
		checks, order, err := smokeChecks(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		tools, err := profileTools(p)
		if err != nil {
			t.Fatal(err)
		}
		tools = append(tools, baseTools...)
		// Every resolved tool is covered, and the order list matches.
		uniq := map[string]bool{}
		for _, tool := range tools {
			uniq[tool] = true
			if checks[tool] == "" {
				t.Errorf("%s: tool %q has no smoke check", p, tool)
			}
		}
		if len(order) != len(uniq) {
			t.Errorf("%s: %d checks for %d distinct tools", p, len(order), len(uniq))
		}
	}
}

// A [smoke] entry naming a tool the suite does not have is dead weight that will rot:
// the tool gets renamed or dropped and the entry silently stops applying.
func TestNoSmokeEntryIsOrphaned(t *testing.T) {
	for _, p := range profileNames() {
		raw, err := profileFS.ReadFile("profiles/" + p + ".toml")
		if err != nil {
			t.Fatal(err)
		}
		var pf profileFile
		if err := toml.Unmarshal(raw, &pf); err != nil {
			t.Fatal(err)
		}
		own := map[string]bool{}
		for _, tool := range pf.Tools {
			own[tool] = true
		}
		// An outer suite may override an inner suite's entry, so a key is legitimate
		// if it is either its own tool or a tool it inherits.
		inherited, err := profileTools(p)
		if err != nil {
			t.Fatal(err)
		}
		inherited = append(inherited, baseTools...)
		for key := range pf.Smoke {
			if !own[key] && !contains(inherited, key) {
				t.Errorf("%s: [smoke] names %q, which the suite does not install", p, key)
			}
		}
	}
}

// An outer suite has to be able to fix a check it inherits, or a composed suite could
// never correct a building block's mistake.
func TestOuterSmokeEntryWins(t *testing.T) {
	inner, err := smokeTable("recon", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := smokeTable("web", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	// web overrides recon's whatweb-free world by adding its own entries; the
	// inherited ones must still be present.
	if outer["wireshark-cli"] != inner["wireshark-cli"] {
		t.Error("web did not inherit recon's smoke entries")
	}
	if outer["ffuf"] == "" {
		t.Error("web's own smoke entries are missing")
	}
}

// The default check has to be the attr name, because that is what makes "every tool is
// covered" true without a table entry per tool.
func TestSmokeDefaultsToTheAttrName(t *testing.T) {
	// Built independently from the three sources smokeChecks merges, then compared.
	// Asserting "some tool uses the default" was the wrong shape: every shipped tool
	// now has an explicit entry, so that assertion passed only by accident and then
	// started failing without anything being broken. This verifies the merge rule and
	// the default formula whether or not a gap happens to exist today.
	for _, p := range profileNames() {
		tools, err := profileTools(p)
		if err != nil {
			t.Fatal(err)
		}
		table, err := smokeTable(p, map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{}
		for _, tool := range append(append([]string{}, baseTools...), tools...) {
			switch {
			case table[tool] != "":
				want[tool] = table[tool] // the suite's own entry wins
			case baseToolChecks[tool] != "":
				want[tool] = baseToolChecks[tool] // then spawn's own base tools
			default:
				want[tool] = "command -v " + tool // then the attr name
			}
		}
		got, order, err := smokeChecks(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(order) != len(want) {
			t.Errorf("%s: %d checks, want %d", p, len(order), len(want))
		}
		for tool, cmd := range want {
			if got[tool] != cmd {
				t.Errorf("%s: check for %q is %q, want %q", p, tool, got[tool], cmd)
			}
		}
	}

	// And the default formula itself, on a tool no table mentions.
	const unlisted = "a-tool-no-suite-ships"
	if cmd := defaultSmokeCheck(unlisted); cmd != "command -v "+unlisted {
		t.Errorf("default check is %q", cmd)
	}
}

// A note is how a suite says what it needs from the host. It must survive composition,
// or pentest would silently drop recon's warning about raw sockets.
func TestNotesSurviveComposition(t *testing.T) {
	notes, err := profileNotes("pentest")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"recon:", "creds:", "active-directory:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("pentest's notes lost %s\ngot:\n%s", want, joined)
		}
	}
	// Notes are informational: a suite must never grant privileges by itself.
	m, err := Parse([]byte("schema = 1\nname = \"p\"\nprofiles = [\"recon\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Caps) != 0 {
		t.Errorf("a profile granted caps %v; privileges must stay in the manifest", m.Caps)
	}
}

// The smoke manifest is what a smoke run actually builds. It must deny egress -- a
// smoke check that reaches the internet is a scan, not a check -- and it must parse.
func TestSmokeManifestIsSealed(t *testing.T) {
	m, path, err := smokeManifest("recon", "spawnsmoketest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	if m.effectiveEgress() != "deny" {
		t.Errorf("a smoke env's egress is %q, want deny", m.effectiveEgress())
	}
	if !contains(m.Caps, "NET_RAW") {
		t.Error("a smoke env needs NET_RAW or half of recon reports a packaging failure")
	}
	if !m.AllowUnfree {
		t.Error("smoke opts in to unfree so a suite's optional unfree tools are testable")
	}
	if !contains(m.resolved, "nmap") {
		t.Error("the smoke manifest did not resolve the suite")
	}
}

// The CI matrix lists the suites to smoke by hand, so it can fall behind the shipped
// set -- and a suite missing from it is a suite nobody ever runs. Asserting the two
// agree is the same guard test/VALIDATION.md gets, for the same reason.
func TestCISmokesEverySuite(t *testing.T) {
	b, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Skip("workflow not readable from here:", err)
	}
	// The matrix line is `suite: [a, b, c]`.
	body := string(b)
	i := strings.Index(body, "suite: [")
	if i < 0 {
		t.Fatal("no smoke matrix in the workflow")
	}
	list := body[i+len("suite: ["):]
	list = list[:strings.IndexByte(list, ']')]
	inCI := map[string]bool{}
	for _, s := range strings.Split(list, ",") {
		inCI[strings.TrimSpace(s)] = true
	}
	for _, p := range profileNames() {
		if !inCI[p] {
			t.Errorf("suite %q ships but CI never smokes it", p)
		}
		delete(inCI, p)
	}
	for leftover := range inCI {
		t.Errorf("CI smokes %q, which is not a shipped suite", leftover)
	}
}
