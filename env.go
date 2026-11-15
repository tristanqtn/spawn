package main

// Container lifecycle. Podman already tracks containers, so spawn keeps no state file
// of its own: the manifest name, the resolved profile and the manifest path live on the
// container as labels, and `podman ps` is the source of truth.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// A multi-user nix install puts its daemon socket here. The socket's DIRECTORY is
// mode 0770 root:nix-users, and that gid is not mapped into a rootless userns, so the
// container cannot traverse it -- so bind-mount the socket file itself (mode 0666).
// Store writes then happen host-side as root, which is why /nix can stay read-only
// inside the env and one env still cannot corrupt another.
const nixDaemonSocket = "/nix/var/nix/daemon-socket/socket"
const envDaemonSocket = "/spawn-nix-daemon"

func dataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "spawn")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		h = "."
	}
	return filepath.Join(h, ".local", "share", "spawn")
}

// envDir holds the env's writable rootfs. --rootfs uses the directory directly with no
// overlay, so anything the env writes outside /nix lands here and survives a restart.
func envDir(name string) string   { return filepath.Join(dataDir(), "envs", name) }
func cname(name string) string    { return "spawn-" + name }
func certPath(prof string) string { return prof + "/etc/ssl/certs/ca-bundle.crt" }

// podmanOut runs podman and returns its trimmed stdout.
func podmanOut(args ...string) (string, error) {
	out, err := exec.Command("podman", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("podman %s: %s", args[0], strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("podman %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(out)), nil
}

// podmanIO runs podman with the terminal attached, for exec and attach.
func podmanIO(args ...string) error {
	c := exec.Command("podman", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// inspect returns "" when the container does not exist.
func inspect(name, format string) string {
	out, err := podmanOut("inspect", "--type", "container", "-f", format, cname(name))
	if err != nil {
		return ""
	}
	return out
}

// createArgs renders the whole podman create invocation, plus a fingerprint of it.
// The fingerprint is what makes the manifest authoritative: a changed mount, port,
// cap or limit has to replace the container just as a changed tool list does, and
// comparing one hash is cheaper and more honest than comparing each field back out
// of podman inspect.
func createArgs(m *Manifest, prof, manifestPath string) ([]string, string, error) {
	root := filepath.Join(envDir(m.Name), "rootfs")
	// There is no base image, so the few directories podman and bash expect have to
	// exist before the container can start.
	for _, d := range []string{"etc", "root", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, "", err
		}
	}
	args := []string{
		// --rootfs is a boolean flag: the path is the first POSITIONAL arg, where an
		// image name would go. Every flag must precede it.
		"--rootfs",
		"-v", "/nix:/nix:ro",
		"-e", "PATH=" + prof + "/bin",
		"-e", "HOME=/root",
		// ponytail: covers curl/openssl/git. Tools that hardcode
		// /etc/ssl/certs/ca-certificates.crt need a real /etc; revisit in M2.
		"-e", "SSL_CERT_FILE=" + certPath(prof),
		"-e", "NIX_SSL_CERT_FILE=" + certPath(prof),
		"-e", "NIX_CONFIG=experimental-features = nix-command flakes",
		// The env's own name, so a prompt or a script can say which box it is in.
		"-e", "SPAWN_ENV=" + m.Name,
		"-w", m.workdir()}
	if _, err := os.Stat(nixDaemonSocket); err == nil {
		args = append(args,
			"-v", nixDaemonSocket+":"+envDaemonSocket,
			"-e", "NIX_REMOTE=unix://"+envDaemonSocket)
	} else {
		fmt.Fprintf(os.Stderr, "spawn: no nix daemon at %s, so nix inside the env is read-only\n", nixDaemonSocket)
	}
	if j := m.Network.Join; j != "" {
		if err := ensureJoinedNetwork(j); err != nil {
			return nil, "", err
		}
		args = append(args, "--network", j)
	}
	rt, err := m.runtimeArgs(filepath.Dir(manifestPath))
	if err != nil {
		return nil, "", err
	}
	args = append(args, rt...)
	pers, err := m.persistArgs()
	if err != nil {
		return nil, "", err
	}
	args = append(args, pers...)
	// Secrets are staged on tmpfs and mounted read-only. The flags name the stage
	// directory, never the plaintext, so the fingerprint below stays secret-free.
	sec, err := m.stageSecrets(filepath.Dir(manifestPath))
	if err != nil {
		return nil, "", err
	}
	args = append(args, sec...)
	// PID 1 just has to stay alive; every real command arrives via podman exec.
	args = append(args, root, prof+"/bin/sleep", "infinity")

	sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	fp := hex.EncodeToString(sum[:])

	full := append([]string{"create", "--name", cname(m.Name),
		"--label", "spawn.name=" + m.Name,
		"--label", "spawn.profile=" + prof,
		"--label", "spawn.manifest=" + manifestPath,
		"--label", "spawn.config=" + fp,
		// Recorded so `spawn up <name>` can attach without the manifest.
		"--label", "spawn.shell=" + m.shellBin(prof)}, args...)
	return full, fp, nil
}

// postStart runs the manifest's hooks inside the env, every time it starts, so a
// started env always matches what the manifest declared.
func postStart(m *Manifest, prof string) error {
	for _, h := range m.Hooks.PostStart {
		out, err := podmanOut("exec", "-e", "PATH="+prof+"/bin", "-w", "/root",
			cname(m.Name), prof+"/bin/bash", "-lc", h)
		if err != nil {
			return fmt.Errorf("hooks.post_start %q: %w", h, err)
		}
		if out != "" {
			fmt.Println(out)
		}
	}
	return nil
}

func up(m *Manifest, manifestPath string, cmd []string) error {
	if err := m.validateHostPaths(filepath.Dir(manifestPath)); err != nil {
		return err
	}
	// Fail here rather than let podman fail with an unreadable conmon error.
	if fstype, why := checkRootfsFS(); why != "" {
		return fmt.Errorf("the env directory %s is on %s (%s), which cannot hold a container rootfs. "+
			"Set XDG_DATA_HOME to a path on the Linux filesystem, e.g. XDG_DATA_HOME=$HOME/.local/share",
			dataDir(), fstype, why)
	}
	prof, err := m.build()
	if err != nil {
		return err
	}
	args, fp, err := createArgs(m, prof, manifestPath)
	if err != nil {
		return err
	}
	// The manifest is the source of truth. If anything it declares has changed,
	// replace the container; the rootfs directory is kept, so nothing the env wrote
	// is lost.
	if cur := inspect(m.Name, `{{index .Config.Labels "spawn.config"}}`); cur != "" && cur != fp {
		fmt.Fprintln(os.Stderr, "spawn: manifest changed, recreating the container (rootfs kept)")
		if _, err := podmanOut("rm", "-f", cname(m.Name)); err != nil {
			return err
		}
	}
	if inspect(m.Name, "{{.Id}}") == "" {
		if _, err := podmanOut(args...); err != nil {
			return err
		}
	}
	// On every up, so that editing a host dotfile and re-running applies it -- even
	// to an env already running, since the rootfs directory IS the container's
	// filesystem. Base identity first, so a manifest can override any of it.
	if err := seedBaseEtc(m.Name, m.shellBin(prof)); err != nil {
		return err
	}
	if err := m.seedShell(prof); err != nil {
		return err
	}
	if err := m.seedFiles(filepath.Dir(manifestPath)); err != nil {
		return err
	}
	// The network files have to exist before the container starts, so the policy can
	// go on at once rather than after something has had a chance to leak.
	if err := m.seedNetwork(prof, filepath.Dir(manifestPath)); err != nil {
		return err
	}
	if inspect(m.Name, "{{.State.Running}}") != "true" {
		if _, err := podmanOut("start", cname(m.Name)); err != nil {
			return err
		}
		// Policy and tunnel before any user hook, so a hook cannot be the thing
		// that leaks.
		if err := m.bringUpNetwork(prof); err != nil {
			return err
		}
		if err := postStart(m, prof); err != nil {
			return err
		}
	}
	ex := []string{"exec", "-e", "PATH=" + prof + "/bin", "-w", m.workdir()}
	if len(cmd) == 0 {
		ex = append(ex, "-it", cname(m.Name), m.shellBin(prof))
	} else {
		// -i so a command can be piped into: `echo x | spawn up env.toml cat`.
		// Without it podman does not attach stdin and the command reads EOF.
		ex = append(ex, "-i", cname(m.Name))
		ex = append(ex, cmd...)
	}
	return podmanIO(ex...)
}

func ls() error {
	out, err := podmanOut("ps", "-a", "--filter", "label=spawn.name", "--format",
		`{{index .Labels "spawn.name"}}`+"\t"+`{{.State}}`+"\t"+`{{.RunningFor}}`+"\t"+
			`{{index .Labels "spawn.manifest"}}`)
	if err != nil {
		return err
	}
	if out == "" {
		fmt.Println(ui.paint(ui.dim, "no envs yet. Write a spawn.toml and run: spawn up"))
		return nil
	}
	t := newTable("NAME", "STATE", "AGE", "PERSIST", "MANIFEST")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		for len(f) < 4 {
			f = append(f, "")
		}
		state := f[1]
		switch state {
		case "running":
			state = ui.paint(ui.green, state)
		case "exited", "created":
			state = ui.paint(ui.dim, state)
		default:
			state = ui.paint(ui.yellow, state)
		}
		persist := ui.paint(ui.dim, "-")
		if dirExists(persistDir(f[0])) {
			persist = "yes"
		}
		// The manifest path is the least important column and the longest, so it is
		// the one that gets shortened.
		t.add(ui.paint(ui.bold, f[0]), state, f[2], persist, ui.paint(ui.dim, truncate(f[3], 44)))
	}
	t.print()
	return nil
}

func stop(name string) error {
	if inspect(name, "{{.Id}}") == "" {
		return fmt.Errorf("no env named %q", name)
	}
	_, err := podmanOut("stop", cname(name))
	// The mount only means anything while the env runs, so do not leave plaintext
	// sitting in tmpfs afterwards.
	clearSecrets(name)
	return err
}

// rm destroys the container and the env's writable rootfs. Anything the env wrote that
// the manifest does not declare is gone, which is the point of a disposable env.
// Directories named in persist are KEPT unless purge is set, so rebuilding from
// scratch costs nothing you declared you wanted to keep.
func rm(name string, purge bool) error {
	if inspect(name, "{{.Id}}") == "" && !dirExists(envDir(name)) && !dirExists(persistDir(name)) {
		return fmt.Errorf("no env named %q", name)
	}
	// Remove the container BEFORE touching the rootfs, and stop if it cannot be
	// removed. Deleting the rootfs out from under a live container loses data and
	// leaves an orphan, and reporting success while doing it is worse still.
	if existed := inspect(name, "{{.Id}}") != ""; existed {
		if _, err := podmanOut("rm", "-f", cname(name)); err != nil {
			return fmt.Errorf("could not remove the container, so the rootfs was left alone: %w", err)
		}
	}
	clearSecrets(name)
	if err := os.RemoveAll(envDir(name)); err != nil {
		return err
	}
	fmt.Printf("removed env %s and its rootfs\n", name)

	p := persistDir(name)
	if !dirExists(p) {
		return nil
	}
	if purge {
		fmt.Printf("purged persisted data at %s\n", p)
		return os.RemoveAll(p)
	}
	fmt.Printf("kept persisted data at %s (spawn rm --purge %s to delete it)\n", p, name)
	return nil
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
