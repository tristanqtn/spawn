package main

import (
	"strings"
	"testing"
)

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		s, err := completionScript(shell)
		if err != nil {
			t.Errorf("%s: %v", shell, err)
			continue
		}
		// Every script has to delegate to __complete, or the candidate logic would
		// have to be reimplemented per shell.
		if !strings.Contains(s, "spawn __complete") {
			t.Errorf("%s script does not call spawn __complete", shell)
		}
		if !strings.Contains(s, "spawn completion "+shell) {
			t.Errorf("%s script does not document how to install itself", shell)
		}
	}
	if _, err := completionScript("powershell"); err == nil {
		t.Error("an unsupported shell should be an error, not an empty script")
	}
}

func TestCompletionCandidates(t *testing.T) {
	// The first word offers every command, with descriptions for zsh.
	first := candidates(nil)
	if len(first) != len(commandOrder) {
		t.Errorf("first word offered %d candidates, want %d", len(first), len(commandOrder))
	}
	for _, c := range first {
		name, desc, found := strings.Cut(c, ":")
		if !found || desc == "" {
			t.Errorf("candidate %q has no description", c)
		}
		if commands[name] == "" {
			t.Errorf("candidate %q is not a real command", name)
		}
	}

	// rm takes --purge; stop does not, since purging is about stored data.
	if !hasCandidate(candidates([]string{"rm"}), "--purge") {
		t.Error("rm should offer --purge")
	}
	if hasCandidate(candidates([]string{"stop"}), "--purge") {
		t.Error("stop should not offer --purge")
	}

	// profiles offers its machine-readable form, which is what CI consumes.
	if !hasCandidate(candidates([]string{"profiles"}), "--names") {
		t.Error("profiles should offer --names")
	}

	// A command that takes no arguments offers nothing, rather than falling back to
	// the command list again.
	for _, cmd := range []string{"ls", "version", "help"} {
		if got := candidates([]string{cmd}); got != nil {
			t.Errorf("%s should offer no arguments, got %v", cmd, got)
		}
	}

	if got := candidates([]string{"completion"}); len(got) != 3 {
		t.Errorf("completion should offer three shells, got %v", got)
	}
	// Past the shell name there is nothing more to say.
	if got := candidates([]string{"completion", "bash"}); got != nil {
		t.Errorf("completion takes one argument, got %v", got)
	}
}

// Every command in the help listing must be dispatchable, and vice versa: a command
// that completes but does not run, or runs but is undocumented, is worse than neither.
func TestCommandListsAgree(t *testing.T) {
	if len(commandOrder) != len(commands) {
		t.Errorf("commandOrder has %d entries, commands has %d", len(commandOrder), len(commands))
	}
	seen := map[string]bool{}
	for _, c := range commandOrder {
		if commands[c] == "" {
			t.Errorf("%q is listed in the help order but has no description", c)
		}
		if seen[c] {
			t.Errorf("%q listed twice", c)
		}
		seen[c] = true
	}
	for c := range commands {
		if !seen[c] {
			t.Errorf("%q has a description but is missing from the help order", c)
		}
	}
}

func hasCandidate(cs []string, want string) bool {
	for _, c := range cs {
		if name, _, _ := strings.Cut(c, ":"); name == want {
			return true
		}
	}
	return false
}

// bash's compgen -W splits on whitespace, so descriptions must not reach it: a
// "value:description" line would become one candidate per word of the description.
// Only the zsh script passes --describe.
func TestOnlyZshAsksForDescriptions(t *testing.T) {
	zsh, _ := completionScript("zsh")
	if !strings.Contains(zsh, "__complete --describe") {
		t.Error("zsh should request descriptions")
	}
	for _, shell := range []string{"bash", "fish"} {
		s, _ := completionScript(shell)
		if strings.Contains(s, "--describe") {
			t.Errorf("%s must not request descriptions: it would split them into separate candidates", shell)
		}
	}
}
