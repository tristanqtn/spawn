package main

import (
	"strings"
	"testing"
)

func TestParseRejects(t *testing.T) {
	bad := map[string]string{
		"wrong schema":      "schema = 2\nname = \"x\"\ntools = [\"nmap\"]",
		"no schema":         "name = \"x\"\ntools = [\"nmap\"]",
		"no name":           "schema = 1\ntools = [\"nmap\"]",
		"nothing declared":  "schema = 1\nname = \"x\"",
		"unknown field":     "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\nvpn = \"lab.ovpn\"",
		"attr injection":    "schema = 1\nname = \"x\"\ntools = [\"nmap ]; evil = \"]",
		"unknown profile":   "schema = 1\nname = \"x\"\nprofiles = [\"nope\"]",
		"profile traversal": "schema = 1\nname = \"x\"\nprofiles = [\"../go\"]",
		"bad allow_insecure": "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n" +
			"allow_insecure = [\"a\\\" ]; evil = \\\"\"]",
	}
	for why, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}
}

func TestParseResolves(t *testing.T) {
	m, err := Parse([]byte("schema = 1\nname = \"recon\"\ntools = [\"nmap\", \"python3Packages.impacket\"]"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Nixpkgs != defaultNixpkgs {
		t.Errorf("nixpkgs not defaulted: %q", m.Nixpkgs)
	}
	e := m.expr()
	for _, want := range []string{"bashInteractive", "coreutils", "cacert", "nix",
		"nmap", "python3Packages.impacket", `name = "spawn-recon"`} {
		if !strings.Contains(e, want) {
			t.Errorf("expr missing %q:\n%s", want, e)
		}
	}
}

// Reproducibility is the pitch, so the default must be a revision. A branch ref would
// resolve to something different next month and nothing would notice.
func TestDefaultNixpkgsIsPinnedToARevision(t *testing.T) {
	rev := strings.TrimPrefix(defaultNixpkgs, "github:NixOS/nixpkgs/")
	if len(rev) != 40 {
		t.Fatalf("default nixpkgs is not a 40-char revision: %q", defaultNixpkgs)
	}
	for _, c := range rev {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("default nixpkgs revision is not hex: %q", rev)
		}
	}
}

func TestLicenceOptIns(t *testing.T) {
	// Off unless the manifest says otherwise: allowing unfree code is the user's call.
	off := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]")
	if !strings.Contains(off.expr(), "allowUnfree = false") {
		t.Error("allowUnfree should default to false")
	}
	if !strings.Contains(off.expr(), "permittedInsecurePackages = [  ]") {
		t.Errorf("expected an empty insecure list:\n%s", off.expr())
	}

	on := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"burpsuite\"]\n"+
		"allow_unfree = true\nallow_insecure = [\"bloodhound-4.3.1\"]")
	e := on.expr()
	if !strings.Contains(e, "allowUnfree = true") {
		t.Error("allow_unfree not propagated")
	}
	if !strings.Contains(e, `permittedInsecurePackages = [ "bloodhound-4.3.1" ]`) {
		t.Errorf("allow_insecure not propagated:\n%s", e)
	}
}

func mustParse(t *testing.T, src string) *Manifest {
	t.Helper()
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestProfilesMergeAndDedup(t *testing.T) {
	// ctf and active-directory both carry john and hashcat.
	m, err := Parse([]byte("schema = 1\nname = \"x\"\nprofiles = [\"ctf\", \"active-directory\"]\ntools = [\"nmap\"]"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, tool := range m.resolved {
		seen[tool]++
	}
	for tool, n := range seen {
		if n > 1 {
			t.Errorf("%q appears %d times", tool, n)
		}
	}
	if seen["john"] != 1 || seen["nmap"] != 1 || seen["bashInteractive"] != 1 {
		t.Errorf("expected the merged set to contain each exactly once: %v", seen)
	}
}

// Every shipped profile must parse and name only valid attributes, or spawn up
// fails on a suite the user did not write.
func TestShippedProfilesAreValid(t *testing.T) {
	names := profileNames()
	if len(names) < 5 {
		t.Fatalf("expected the five suites, got %v", names)
	}
	for _, n := range names {
		ts, err := profileTools(n)
		if err != nil {
			t.Errorf("%s: %v", n, err)
			continue
		}
		if len(ts) == 0 {
			t.Errorf("%s: no tools", n)
		}
		for _, tool := range ts {
			if !attrRe.MatchString(tool) {
				t.Errorf("%s: bad attr %q", n, tool)
			}
		}
	}
}
