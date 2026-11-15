package main

import (
	"strings"
	"testing"
)

const fakeProf = "/nix/store/fake-prof"

func TestShellValidationRejects(t *testing.T) {
	bad := map[string]string{
		"unknown shell":                  "[shell]\nuse = \"fish\"",
		"unknown prompt":                 "[shell]\nprompt = \"powerlevel10k\"",
		"alias with a space in the name": "[shell]\naliases = { \"ll x\" = \"eza\" }",
		"alias with a quote":             "[shell]\naliases = { \"l'x\" = \"eza\" }",
	}
	for why, field := range bad {
		src := "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n" + field + "\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}
}

// Declaring shell.use = "zsh" and then having to remember to add zsh to tools would
// be a trap, so [shell] pulls in what it needs.
func TestShellImpliesItsPackages(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[shell]\nuse = \"zsh\"\nprompt = \"starship\"\n")
	for _, want := range []string{"zsh", "starship"} {
		if !m.has(want) {
			t.Errorf("[shell] did not pull in %s", want)
		}
	}
	if !strings.Contains(m.shellBin(fakeProf), "/bin/zsh") {
		t.Errorf("shellBin = %q, want the zsh in the profile", m.shellBin(fakeProf))
	}

	// Without [shell] nothing is added and bash stays the default.
	plain := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]")
	if plain.has("zsh") || plain.has("starship") {
		t.Error("a manifest with no [shell] should not gain shell packages")
	}
	if !strings.HasSuffix(plain.shellBin(fakeProf), "/bin/bash") {
		t.Error("bash should be the default shell")
	}
}

// Persisted history needs somewhere persistent to live, so [shell] adds the entry
// rather than leaving the user to discover that history vanished on rm.
func TestShellHistoryAddsPersist(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n[shell]\nuse = \"zsh\"\n")
	found := false
	for _, p := range m.Persist {
		if p == historyDir {
			found = true
		}
	}
	if !found {
		t.Errorf("history dir not persisted: %v", m.Persist)
	}
	if !strings.Contains(m.rc(fakeProf), "HISTFILE="+historyDir) {
		t.Error("HISTFILE does not point at the persisted directory")
	}

	// Opting out must not add it.
	off := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n[shell]\nhistory = false\n")
	for _, p := range off.Persist {
		if p == historyDir {
			t.Error("history = false still persisted the history directory")
		}
	}
	if strings.Contains(off.rc(fakeProf), "HISTFILE") {
		t.Error("history = false still set HISTFILE")
	}
}

// Integrations are wired up from the package list, not from a list the user keeps in
// step by hand. A tool that is absent must not be referenced at all.
func TestIntegrationsFollowThePackages(t *testing.T) {
	with := mustParse(t, "schema = 1\nname = \"x\"\n"+
		"tools = [\"fzf\", \"zoxide\", \"direnv\", \"zsh-autosuggestions\", \"zsh-syntax-highlighting\"]\n"+
		"[shell]\nuse = \"zsh\"\n")
	rc := with.rc(fakeProf)
	for _, want := range []string{"fzf-share", "zoxide init zsh", "direnv hook zsh",
		fakeProf + "/share/zsh-autosuggestions/zsh-autosuggestions.zsh"} {
		if !strings.Contains(rc, want) {
			t.Errorf("rc is missing %q:\n%s", want, rc)
		}
	}
	// Syntax highlighting has to be sourced after autosuggestions or it misses
	// the widgets registered earlier.
	if strings.Index(rc, "zsh-syntax-highlighting") < strings.Index(rc, "zsh-autosuggestions") {
		t.Error("syntax highlighting must be sourced last")
	}

	bare := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n[shell]\nuse = \"zsh\"\n")
	bareRC := bare.rc(fakeProf)
	for _, absent := range []string{"fzf", "zoxide", "direnv", "starship"} {
		if strings.Contains(bareRC, absent) {
			t.Errorf("rc references %q, which is not in the env:\n%s", absent, bareRC)
		}
	}
}

func TestRCQuotesAliasesAndGuardsNonInteractive(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"box\"\ntools = [\"nmap\"]\n"+
		"[shell]\naliases = { x = \"echo it's quoted\" }\ninit = \"export A=1\"\n")
	rc := m.rc(fakeProf)
	// An alias value is arbitrary shell, so the quoting has to be exact.
	if !strings.Contains(rc, `alias x='echo it'\''s quoted'`) {
		t.Errorf("alias not safely quoted:\n%s", rc)
	}
	// An rc read by a non-interactive shell must not try to set up a line editor.
	if !strings.Contains(rc, "case $- in *i*)") {
		t.Error("rc does not guard against non-interactive shells")
	}
	// shell.init goes last so it can override everything above it.
	if strings.Index(rc, "export A=1") < strings.Index(rc, "alias x=") {
		t.Error("shell.init should come after the generated lines")
	}
	// With no starship the prompt still names the env, since knowing which box you
	// are in is the point.
	if !strings.Contains(rc, "box> ") {
		t.Errorf("prompt does not name the env:\n%s", rc)
	}
}
