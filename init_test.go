package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The template is the first thing anyone sees, so it has to parse and validate as a
// real manifest -- including its dotfile references resolving once init has written
// them. A broken template is worse than no template.
func TestTemplateIsAWorkingManifest(t *testing.T) {
	dir := t.TempDir()
	if err := initKit(dir, false, false); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "spawn.toml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal("the shipped template does not parse:", err)
	}
	// Every mount, device and files source it names must exist after init, or the
	// first `spawn up` fails on a file spawn itself was supposed to write.
	if err := m.validateHostPaths(dir); err != nil {
		t.Error("the template references something init did not create:", err)
	}

	// The things the template promises.
	if m.workdir() != "/workspace" {
		t.Errorf("workdir = %q, want /workspace", m.workdir())
	}
	if m.Shell.use() != "zsh" || !m.Shell.usesStarship() {
		t.Errorf("template shell = %q/%q", m.Shell.use(), m.Shell.Prompt)
	}
	for _, want := range []string{"/root/.config/starship.toml", "/root/.tmux.conf"} {
		if _, ok := m.Files[want]; !ok {
			t.Errorf("template does not declare %s", want)
		}
	}
}

// init must not clobber files that are the whole point of the exercise.
func TestInitDoesNotOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if err := initKit(dir, false, false); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(dir, "dotfiles", "tmux.conf")
	if err := os.WriteFile(mine, []byte("# my own config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initKit(dir, false, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(mine); string(b) != "# my own config\n" {
		t.Error("init overwrote an edited dotfile")
	}
	// --force is the explicit way back to the shipped version.
	if err := initKit(dir, true, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(mine); string(b) == "# my own config\n" {
		t.Error("--force did not restore the template")
	}
}

// The mount source has to exist or the first up fails, so init creates it.
func TestInitCreatesTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	if err := initKit(dir, false, false); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "workspace")); err != nil || !fi.IsDir() {
		t.Error("init did not create workspace/")
	}
}

func TestWorkdirDefaultsAndValidates(t *testing.T) {
	plain := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]")
	if plain.workdir() != "/root" {
		t.Errorf("default workdir = %q, want /root", plain.workdir())
	}
	set := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\nworkdir = \"/workspace/\"")
	if set.workdir() != "/workspace" {
		t.Errorf("workdir = %q, want it cleaned to /workspace", set.workdir())
	}
	if _, err := Parse([]byte("schema = 1\nname = \"x\"\ntools = [\"nmap\"]\nworkdir = \"rel\"")); err == nil {
		t.Error("a relative workdir should be rejected")
	}
}

// The built-in Exegol prompt and the template's starship.toml should not drift apart,
// since they are meant to be the same prompt with and without a file to edit.
func TestExegolPromptMatchesTheTemplate(t *testing.T) {
	tpl, err := templateFS.ReadFile("templates/dotfiles/starship.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`time_format = "%b %d, %Y - %H:%M:%S (%Z)"`, // the Exegol clock
		"[palettes.dracula]",
		"env_var.SPAWN_ENV", // the env name in the prompt
	} {
		if !strings.Contains(string(tpl), want) {
			t.Errorf("template starship.toml is missing %q", want)
		}
		if !strings.Contains(draculaStarship, want) {
			t.Errorf("built-in exegol prompt is missing %q", want)
		}
	}
}

// --engagement has to produce a manifest that actually parses and validates, with the
// pentest profile and the privileges scanning needs -- a template that does not build
// is worse than no template.
func TestEngagementTemplateIsAWorkingManifest(t *testing.T) {
	dir := t.TempDir()
	if err := initKit(dir, false, true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "spawn.toml"))
	if err != nil {
		t.Fatal("--engagement did not write spawn.toml:", err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal("the engagement template does not parse:", err)
	}
	if !contains(m.Profiles, "pentest") {
		t.Errorf("profiles = %v, want pentest", m.Profiles)
	}
	// Without NET_RAW, nmap silently falls back to a connect scan; the template exists
	// partly so nobody has to rediscover that.
	if !contains(m.Caps, "NET_RAW") {
		t.Errorf("caps = %v, want NET_RAW", m.Caps)
	}
	if !contains(m.Persist, "/loot") {
		t.Errorf("persist = %v, want /loot", m.Persist)
	}
	if m.workdir() != "/workspace" {
		t.Errorf("workdir = %q", m.workdir())
	}
	// It resolves the whole daily driver, not a stub.
	if len(m.resolved) < 100 {
		t.Errorf("resolved only %d packages", len(m.resolved))
	}
	// And the plain template must NOT be written alongside it: two manifests in one
	// directory is exactly the confusion `spawn up` cannot resolve for you.
	if _, err := os.Stat(filepath.Join(dir, "engagement.toml")); err == nil {
		t.Error("engagement.toml was written as well as spawn.toml")
	}
	// The dotfiles the manifest references have to be there too.
	for _, f := range []string{"dotfiles/starship.toml", "dotfiles/tmux.conf", "resources/README.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}
}
