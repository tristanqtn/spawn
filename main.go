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

// version is stamped by the release build; "dev" when built from a working copy.
var version = "dev"

// A revision, never a branch: "nixos-unstable" would resolve to something different
// next month, and rebuilding identically months later is the whole point. This
// constant IS the lock -- it moves when spawn is upgraded, not when nixpkgs is, so a
// manifest with no nixpkgs field still pins. Override per manifest to pick another.
// nixos-unstable as of 2026-11-12.
const defaultNixpkgs = "github:NixOS/nixpkgs/d5cc6833999746cffdfe0598f7bc801a57b887a9"

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

	// Licence and security opt-ins. These are manifest fields rather than an
	// environment variable spawn sets for you, because allowing unfree or insecure
	// code is the user's decision and should be visible in review. burpsuite,
	// wpscan and volatility3 need the first; the archived bloodhound needs the second.
	AllowUnfree   bool     `toml:"allow_unfree"`
	AllowInsecure []string `toml:"allow_insecure"`

	// Runtime surface. caps and devices are deliberately first-class and visible
	// rather than hidden behind wrapper flags: without NET_RAW, ping fails at exec
	// and nmap dies with "dnet: Failed to open device eth0", and neither error names
	// the cause. The privilege an env holds is exactly what a user needs to reason
	// about.
	// Where a shell starts, and what the prompt shows. Exegol uses /workspace.
	Workdir string            `toml:"workdir"`
	Env     map[string]string `toml:"env"`
	Mounts  []string          `toml:"mounts"`
	Ports   []string          `toml:"ports"`
	Caps    []string          `toml:"caps"`
	Devices []string          `toml:"devices"`
	// The generated shell. See shell.go.
	Shell shellConfig `toml:"shell"`
	// Config files copied into the env, writable, so a tool that rewrites its own
	// config works. Keyed by the path inside the env. See files.go.
	Files map[string]fileSpec `toml:"files"`
	// Secrets, referenced by path to an ENCRYPTED file and exposed read-only at
	// /run/secrets/<name>. Never a nix store path: /nix/store is world-readable and
	// permanent. See secrets.go.
	Secrets map[string]string `toml:"secrets"`
	// Directories that outlive the env itself. The rootfs already survives a restart
	// and a manifest change, so what persist buys is surviving `spawn rm` and a
	// rebuild from scratch: a tool upgrade should never cost you your notes.
	Persist []string `toml:"persist"`
	Limits  struct {
		CPUs   string `toml:"cpus"`
		Memory string `toml:"memory"`
		PIDs   int    `toml:"pids"`
	} `toml:"limits"`
	Hooks struct {
		PostStart []string `toml:"post_start"`
	} `toml:"hooks"`

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
	var p profileFile
	if err := toml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return p.Tools, nil
}

// profileFile is a shipped suite: a tool list plus one line saying what it is for,
// so `spawn profiles` can be read without opening the repository.
type profileFile struct {
	Description string   `toml:"description"`
	Tools       []string `toml:"tools"`
}

func profileDescription(name string) (string, error) {
	b, err := profileFS.ReadFile("profiles/" + name + ".toml")
	if err != nil {
		return "", err
	}
	var p profileFile
	if err := toml.Unmarshal(b, &p); err != nil {
		return "", err
	}
	return p.Description, nil
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
	// [shell] implies its own packages: declaring shell.use = "zsh" and then having
	// to remember to add zsh to tools would be a trap.
	for _, t := range m.Shell.packages() {
		add(t)
	}
	// permittedInsecurePackages entries are versioned names like "bloodhound-4.3.1".
	// nixStrings quotes them, so this is shape validation rather than the injection
	// guard, but a typo here fails late and confusingly otherwise.
	for _, p := range m.AllowInsecure {
		if !attrRe.MatchString(p) {
			return nil, fmt.Errorf("allow_insecure %q is not a versioned package name", p)
		}
	}
	if m.Nixpkgs == "" {
		m.Nixpkgs = defaultNixpkgs
	}
	if err := m.validateRuntime(); err != nil {
		return nil, err
	}
	if err := m.validateFiles(); err != nil {
		return nil, err
	}
	if err := m.validateShell(); err != nil {
		return nil, err
	}
	// Persisted history needs somewhere persistent to live, so [shell] adds it
	// rather than making the user wire up a persist entry by hand.
	if m.Shell.persistHistory() && m.shadowedBy(historyDir) == "" {
		m.Persist = append(m.Persist, historyDir)
	}
	return &m, nil
}

func nixSystem() string {
	if runtime.GOARCH == "arm64" {
		return "aarch64-linux"
	}
	return "x86_64-linux"
}

// nixStrings renders a Go slice as a nix list of quoted strings.
func nixStrings(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, " ")
}

// expr imports nixpkgs rather than using the flake's legacyPackages, because
// legacyPackages carries a fixed config and the licence opt-ins have to be set here.
func (m *Manifest) expr() string {
	return fmt.Sprintf(`let
  fl = builtins.getFlake %q;
  pkgs = import fl.outPath {
    system = %q;
    config = { allowUnfree = %t; permittedInsecurePackages = [ %s ]; };
  };
in pkgs.buildEnv { name = "spawn-%s"; paths = with pkgs; [ %s ]; }`,
		m.Nixpkgs, nixSystem(), m.AllowUnfree, nixStrings(m.AllowInsecure),
		m.Name, strings.Join(m.resolved, " "))
}

func nixCmd(args ...string) *exec.Cmd {
	c := exec.Command("nix", args...)
	c.Env = append(os.Environ(), "NIX_CONFIG=experimental-features = nix-command flakes")
	return c
}

// runQuiet runs a command and returns stdout only. Stderr is deliberately dropped by
// the caller when the output could contain secret material.
func runQuiet(bin string, args ...string) ([]byte, error) {
	return exec.Command(bin, args...).Output()
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
		// With no output there is nothing to show, and reporting only "does not
		// evaluate" blames the manifest for a missing nix.
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return "", fmt.Errorf("%s", msg)
		}
		return "", fmt.Errorf("nix eval failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

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

// absPath makes a manifest path absolute, since it is recorded on the container and
// has to still mean something from another directory.
func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
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
		printUsage()
		return
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "help", "-h", "--help":
		printUsage()
	case "version", "--version":
		fmt.Printf("spawn %s, nixpkgs %s\n", version, shortRev(defaultNixpkgs))
	case "completion":
		if len(args) != 1 {
			die(fmt.Errorf("usage: spawn completion bash|zsh|fish"))
		}
		script, err := completionScript(args[0])
		if err != nil {
			die(err)
		}
		fmt.Print(script)
	case "__complete":
		// Hidden: this is what the shell completion scripts call.
		complete(args)
	case "init":
		dir, force := ".", false
		for _, a := range args {
			switch a {
			case "--force", "-f":
				force = true
			default:
				dir = a
			}
		}
		if err := initKit(dir, force); err != nil {
			die(err)
		}
	case "profiles":
		// --names is the stable, parseable form. The table is for humans and its
		// header and rule are not contractual: a CI step that awk'd the table
		// started treating "SUITE" and "-----" as suite names the moment the table
		// gained a header.
		if len(args) == 1 && args[0] == "--names" {
			for _, n := range profileNames() {
				fmt.Println(n)
			}
			return
		}
		if len(args) > 0 {
			die(fmt.Errorf("usage: spawn profiles [--names]"))
		}
		if err := listProfiles(); err != nil {
			die(err)
		}
	case "check":
		if err := requireDeps(depNix); err != nil {
			die(err)
		}
		path, _ := manifestArg(args)
		m := load(path)
		drv, err := m.check()
		if err != nil {
			die(fmt.Errorf("%s does not evaluate:\n%s", path, err))
		}
		t := newTable()
		t.add("env", ui.paint(ui.bold, m.Name))
		if len(m.Profiles) > 0 {
			t.add("suites", strings.Join(m.Profiles, ", "))
		}
		t.add("packages", fmt.Sprint(len(m.resolved)))
		t.add("nixpkgs", shortRev(m.Nixpkgs))
		if len(m.Secrets) > 0 {
			t.add("secrets", strings.Join(sortedKeys(m.Secrets), ", "))
		}
		if len(m.Persist) > 0 {
			t.add("persist", strings.Join(m.Persist, ", "))
		}
		t.add("derivation", ui.paint(ui.dim, drv))
		t.print()
		fmt.Println(ui.paint(ui.green, "evaluates; nothing was downloaded"))
	case "up":
		if err := requireDeps(depNix, depPodman); err != nil {
			die(err)
		}
		if err := upTarget(resolveTarget(args)); err != nil {
			die(err)
		}
	case "doctor":
		path, _ := manifestArg(args)
		// Unlike the other commands, doctor is useful with no manifest at all.
		if _, err := os.Stat(path); err != nil {
			path = ""
		}
		if err := doctor(path); err != nil {
			die(err)
		}
	case "ls":
		if err := requireDeps(depPodman); err != nil {
			die(err)
		}
		if err := ls(); err != nil {
			die(err)
		}
	case "stop":
		if err := requireDeps(depPodman); err != nil {
			die(err)
		}
		if err := stop(arg1(args, "stop")); err != nil {
			die(err)
		}
	case "rm":
		if err := requireDeps(depPodman); err != nil {
			die(err)
		}
		purge := len(args) > 0 && args[0] == "--purge"
		if purge {
			args = args[1:]
		}
		if err := rm(arg1(args, "rm [--purge]"), purge); err != nil {
			die(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "spawn: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

// listProfiles shows the built-in suites with what each is for, so choosing one does
// not require opening the repository.
func listProfiles() error {
	t := newTable("SUITE", "TOOLS", "FOR")
	for _, n := range profileNames() {
		ts, err := profileTools(n)
		if err != nil {
			return err
		}
		d, err := profileDescription(n)
		if err != nil {
			return err
		}
		t.add(n, fmt.Sprint(len(ts)), ui.paint(ui.dim, d))
	}
	t.print()
	return nil
}
