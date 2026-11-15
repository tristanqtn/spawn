// spawn — declarative, disposable environments.
//
// Mechanism (settled by spike/w1-nix-seam.sh): a nix closure brings its own glibc,
// so an env is the host /nix mounted read-only over an EMPTY rootfs. No base image,
// no Containerfile, no registry. Everything in the env, including the shell, comes
// from the profile.
package main

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const schemaVersion = 1

// ponytail: a branch ref, not a pin. M2 locks it to a rev.
const defaultNixpkgs = "github:NixOS/nixpkgs/nixos-unstable"

// With no base image there is no /bin/sh and no /etc/ssl, so every env gets a
// userland. cacert is not optional: without it every TLS client in the env fails.
// nix is included so an env can add a package it turns out to need without a rebuild.
var baseTools = []string{"bashInteractive", "coreutils", "cacert", "nix"}

// Attr names reach a nix expression and a container name, so they are a trust boundary.
var attrRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*$`)

//go:embed profiles/*.toml
var profileFS embed.FS

type Manifest struct {
	Schema   int      `toml:"schema"`
	Name     string   `toml:"name"`
	Profiles []string `toml:"profiles"`
	Tools    []string `toml:"tools"`
	Nixpkgs  string   `toml:"nixpkgs"`

	resolved []string // baseTools + every profile's tools + tools, deduplicated
}

func profileNames() []string {
	es, _ := profileFS.ReadDir("profiles")
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(e.Name(), ".toml"))
	}
	sort.Strings(out)
	return out
}

func profileTools(name string) ([]string, error) {
	// Reject path separators before touching the FS: a profile name is a bare word.
	if !attrRe.MatchString(name) {
		return nil, fmt.Errorf("profile %q is not a bare name", name)
	}
	b, err := profileFS.ReadFile("profiles/" + name + ".toml")
	if err != nil {
		return nil, fmt.Errorf("no such profile %q (have: %s)", name, strings.Join(profileNames(), ", "))
	}
	var p struct {
		Tools []string `toml:"tools"`
	}
	if err := toml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return p.Tools, nil
}

func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	md, err := toml.Decode(string(b), &m)
	if err != nil {
		return nil, err
	}
	if u := md.Undecoded(); len(u) > 0 {
		return nil, fmt.Errorf("unknown field %q", u[0].String())
	}
	if m.Schema != schemaVersion {
		return nil, fmt.Errorf("manifest schema = %d, this spawn speaks schema %d", m.Schema, schemaVersion)
	}
	if !attrRe.MatchString(m.Name) {
		return nil, fmt.Errorf("name %q is empty or not [A-Za-z0-9_.+-]", m.Name)
	}
	if len(m.Profiles) == 0 && len(m.Tools) == 0 {
		return nil, fmt.Errorf("declare at least one of profiles or tools (profiles available: %s)",
			strings.Join(profileNames(), ", "))
	}

	seen := map[string]bool{}
	add := func(t string) error {
		if !attrRe.MatchString(t) {
			return fmt.Errorf("tool %q is not a nixpkgs attribute name", t)
		}
		if !seen[t] {
			seen[t] = true
			m.resolved = append(m.resolved, t)
		}
		return nil
	}
	for _, t := range baseTools {
		add(t)
	}
	for _, p := range m.Profiles {
		ts, err := profileTools(p)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if err := add(t); err != nil {
				return nil, fmt.Errorf("profile %q: %w", p, err)
			}
		}
	}
	for _, t := range m.Tools {
		if err := add(t); err != nil {
			return nil, err
		}
	}
	if m.Nixpkgs == "" {
		m.Nixpkgs = defaultNixpkgs
	}
	return &m, nil
}

func nixSystem() string {
	if runtime.GOARCH == "arm64" {
		return "aarch64-linux"
	}
	return "x86_64-linux"
}

func (m *Manifest) expr() string {
	return fmt.Sprintf(`let fl = builtins.getFlake %q; pkgs = fl.legacyPackages.%s;
in pkgs.buildEnv { name = "spawn-%s"; paths = with pkgs; [ %s ]; }`,
		m.Nixpkgs, nixSystem(), m.Name, strings.Join(m.resolved, " "))
}

func nixCmd(args ...string) *exec.Cmd {
	c := exec.Command("nix", args...)
	c.Env = append(os.Environ(), "NIX_CONFIG=experimental-features = nix-command flakes")
	return c
}

// build resolves the manifest to a single nix store path.
func (m *Manifest) build() (string, error) {
	c := nixCmd("build", "--impure", "--no-link", "--print-out-paths", "--expr", m.expr())
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("nix build: %w", err)
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return "", fmt.Errorf("nix build printed no store path")
	}
	return p, nil
}

// check evaluates the manifest without building or downloading anything. Evaluation
// is what surfaces a bad attribute name, an unfree licence or an insecure package,
// so this is the cheap gate for a suite that would otherwise cost GBs to discover.
func (m *Manifest) check() (string, error) {
	out, err := nixCmd("eval", "--impure", "--raw", "--expr", "("+m.expr()+").drvPath").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

const usage = `usage: spawn up    [manifest.toml] [cmd...]   build an env and enter it
       spawn check [manifest.toml]           evaluate it, download nothing
       spawn ls                              list envs
       spawn stop <name>                     stop an env, keeping its rootfs
       spawn rm   <name>                     destroy an env and its rootfs
       spawn profiles                        list the built-in suites`

// manifestArg pulls an optional manifest path off the front of the args.
func manifestArg(args []string) (string, []string) {
	if len(args) > 0 && strings.HasSuffix(args[0], ".toml") {
		return args[0], args[1:]
	}
	return "spawn.toml", args
}

func load(path string) *Manifest {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	m, err := Parse(b)
	if err != nil {
		die(fmt.Errorf("%s: %s", path, err))
	}
	return m
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "spawn:", err)
	os.Exit(1)
}

// arg1 returns the single required argument for a command that names an env.
func arg1(args []string, cmd string) string {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: spawn %s <name>\n", cmd)
		os.Exit(2)
	}
	return args[0]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "profiles":
		for _, n := range profileNames() {
			ts, err := profileTools(n)
			if err != nil {
				die(err)
			}
			fmt.Printf("%-18s %d tools\n", n, len(ts))
		}
	case "check":
		path, _ := manifestArg(args)
		m := load(path)
		drv, err := m.check()
		if err != nil {
			die(fmt.Errorf("%s does not evaluate:\n%s", path, err))
		}
		fmt.Printf("%s: %d packages ok -> %s\n", m.Name, len(m.resolved), drv)
	case "up":
		path, rest := manifestArg(args)
		abs, err := filepath.Abs(path)
		if err != nil {
			die(err)
		}
		if err := up(load(path), abs, rest); err != nil {
			die(err)
		}
	case "ls":
		if err := ls(); err != nil {
			die(err)
		}
	case "stop":
		if err := stop(arg1(args, "stop")); err != nil {
			die(err)
		}
	case "rm":
		if err := rm(arg1(args, "rm")); err != nil {
			die(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "spawn: unknown command %q\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}
}
