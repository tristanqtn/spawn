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

// A multi-user nix install puts its daemon socket here. The socket's DIRECTORY is
// mode 0770 root:nix-users, and that gid is not mapped into a rootless userns, so the
// container cannot traverse it -- so bind-mount the socket file itself (mode 0666).
// Store writes then happen host-side as root, which is why /nix can stay read-only
// inside the env and one env still cannot corrupt another.
const nixDaemonSocket = "/nix/var/nix/daemon-socket/socket"
const envDaemonSocket = "/spawn-nix-daemon"

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

// build resolves the manifest to a single nix store path.
func (m *Manifest) build() (string, error) {
	c := exec.Command("nix", "build", "--impure", "--no-link", "--print-out-paths", "--expr", m.expr())
	c.Env = append(os.Environ(), "NIX_CONFIG=experimental-features = nix-command flakes")
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
	c := exec.Command("nix", "eval", "--impure", "--raw", "--expr", "("+m.expr()+").drvPath")
	c.Env = append(os.Environ(), "NIX_CONFIG=experimental-features = nix-command flakes")
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func certPath(prof string) string { return prof + "/etc/ssl/certs/ca-bundle.crt" }

func up(m *Manifest, cmd []string) error {
	prof, err := m.build()
	if err != nil {
		return err
	}
	// Ephemeral rootfs: writes outside /nix are lost on exit. Persistence is M2.
	root, err := os.MkdirTemp("", "spawn-rootfs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	for _, d := range []string{"etc", "root", "tmp"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			return err
		}
	}
	// --rootfs is a boolean flag: the path is the first POSITIONAL arg, where an
	// image name would go. Every flag must precede it.
	args := []string{"run", "--rm", "--name", "spawn-" + m.Name, "--rootfs",
		"-v", "/nix:/nix:ro",
		"-e", "PATH=" + prof + "/bin", "-e", "HOME=/root", "-w", "/root",
		// ponytail: covers curl/openssl/git. Tools that hardcode
		// /etc/ssl/certs/ca-certificates.crt need a real /etc; revisit in M2.
		"-e", "SSL_CERT_FILE=" + certPath(prof), "-e", "NIX_SSL_CERT_FILE=" + certPath(prof),
		"-e", "NIX_CONFIG=experimental-features = nix-command flakes"}
	if _, err := os.Stat(nixDaemonSocket); err == nil {
		args = append(args,
			"-v", nixDaemonSocket+":"+envDaemonSocket,
			"-e", "NIX_REMOTE=unix://"+envDaemonSocket)
	} else {
		fmt.Fprintf(os.Stderr, "spawn: no nix daemon at %s, so nix inside the env is read-only\n", nixDaemonSocket)
	}
	if len(cmd) == 0 {
		args = append(args, "-it", root, prof+"/bin/bash")
	} else {
		args = append(args, root)
		args = append(args, cmd...)
	}
	c := exec.Command("podman", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

const usage = `usage: spawn up    [manifest.toml] [cmd...]   build and enter an env
       spawn check [manifest.toml]           evaluate it, download nothing
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
		fmt.Fprintln(os.Stderr, "spawn:", err)
		os.Exit(1)
	}
	m, err := Parse(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spawn: %s: %s\n", path, err)
		os.Exit(1)
	}
	return m
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "profiles":
		for _, n := range profileNames() {
			ts, err := profileTools(n)
			if err != nil {
				fmt.Fprintln(os.Stderr, "spawn:", err)
				os.Exit(1)
			}
			fmt.Printf("%-18s %d tools\n", n, len(ts))
		}
	case "check":
		path, _ := manifestArg(os.Args[2:])
		m := load(path)
		drv, err := m.check()
		if err != nil {
			fmt.Fprintf(os.Stderr, "spawn: %s does not evaluate:\n%s\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("%s: %d packages ok -> %s\n", m.Name, len(m.resolved), drv)
	case "up":
		path, rest := manifestArg(os.Args[2:])
		if err := up(load(path), rest); err != nil {
			fmt.Fprintln(os.Stderr, "spawn:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "spawn: unknown command %q\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}
}
