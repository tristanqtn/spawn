package main

import (
	"strings"
	"testing"
)

// A missing dependency has to say which one and what to do, because the raw Go error
// is `exec: "nix": executable file not found in $PATH`, which reads like a spawn bug.
func TestMissingDependencyIsActionable(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // nothing on PATH at all

	for _, d := range []dep{depNix, depPodman} {
		err := d.require()
		if err == nil {
			t.Fatalf("%s: expected an error with an empty PATH", d.bin)
		}
		msg := err.Error()
		for _, want := range []string{d.bin, "spawn doctor"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error should mention %q:\n%s", d.bin, want, msg)
			}
		}
		// It must say how to get it, not just that it is absent.
		if !strings.Contains(msg, "install") && !strings.Contains(msg, "Install") {
			t.Errorf("%s: error gives no way to install it:\n%s", d.bin, msg)
		}
	}

	// requireDeps reports the FIRST missing dependency rather than a vague summary.
	err := requireDeps(depNix, depPodman)
	if err == nil || !strings.Contains(err.Error(), "nix") {
		t.Errorf("requireDeps should report nix first, got %v", err)
	}
}

// Without nix, `spawn check` once printed "does not evaluate:" and nothing else,
// which blames the manifest for a missing dependency.
func TestCheckWithoutNixExplainsItself(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	m, err := Parse([]byte("schema = 1\nname = \"x\"\ntools = [\"nmap\"]"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.check()
	if err == nil {
		t.Fatal("expected an error with no nix on PATH")
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Error("the error is empty, so the user is told nothing")
	}
	if !strings.Contains(err.Error(), "nix") {
		t.Errorf("the error should name nix:\n%s", err)
	}
}
