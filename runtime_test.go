package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeValidationRejects(t *testing.T) {
	bad := map[string]string{
		"port shape":            `ports = ["lol"]`,
		"port missing half":     `ports = ["8080"]`,
		"cap lowercase":         `caps = ["cap_net_admin"]`,
		"device outside dev":    `devices = ["/etc/shadow"]`,
		"mount one-sided":       `mounts = ["/tmp"]`,
		"mount relative target": `mounts = ["/tmp:loot"]`,
		"env key with space":    `env = { "bad key" = "v" }`,
		"cpus not a number":     `[limits]` + "\n" + `cpus = "many"`,
		"memory shape":          `[limits]` + "\n" + `memory = "lots"`,
	}
	for why, field := range bad {
		src := "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n" + field + "\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted %s", why, field)
		}
	}
}

func TestRuntimeArgs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "loot"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"env = { B = \"2\", A = \"1\" }\n"+
		"mounts = [\"./loot:/loot:ro\"]\nports = [\"127.0.0.1:18080:8080\"]\n"+
		"caps = [\"NET_ADMIN\"]\n[limits]\ncpus = \"2\"\nmemory = \"1g\"\npids = 256\n")
	args, err := m.runtimeArgs(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{
		"-e A=1", "-e B=2", // sorted, so two creates of one manifest compare cleanly
		filepath.ToSlash(filepath.Join(dir, "loot")) + ":/loot:ro",
		"-p 127.0.0.1:18080:8080", "--cap-add NET_ADMIN",
		"--cpus 2", "--memory 1g", "--pids-limit 256",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}
	// A relative mount must resolve against the manifest, not the working directory.
	if strings.Contains(got, " ./loot") {
		t.Error("relative mount was not made absolute")
	}
}

// A missing host path has to be caught before the nix build: finding out after a
// multi-gigabyte download is a bad trade.
func TestMissingHostPathCaughtBeforeBuild(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\nmounts = [\"./nope-xyz:/x\"]")
	if err := m.validateHostPaths(t.TempDir()); err == nil {
		t.Error("missing mount source accepted")
	}
}
