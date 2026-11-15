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
	"text/tabwriter"
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
		"-w", "/root"}
	if _, err := os.Stat(nixDaemonSocket); err == nil {
		args = append(args,
			"-v", nixDaemonSocket+":"+envDaemonSocket,
			"-e", "NIX_REMOTE=unix://"+envDaemonSocket)
	} else {
		fmt.Fprintf(os.Stderr, "spawn: no nix daemon at %s, so nix inside the env is read-only\n", nixDaemonSocket)
	}
	rt, err := m.runtimeArgs(filepath.Dir(manifestPath))
	if err != nil {
		return nil, "", err
	}
	args = append(args, rt...)
	// PID 1 just has to stay alive; every real command arrives via podman exec.
	args = append(args, root, prof+"/bin/sleep", "infinity")

	sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	fp := hex.EncodeToString(sum[:])

	full := append([]string{"create", "--name", cname(m.Name),
		"--label", "spawn.name=" + m.Name,
		"--label", "spawn.profile=" + prof,
		"--label", "spawn.manifest=" + manifestPath,
		"--label", "spawn.config=" + fp}, args...)
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
	if inspect(m.Name, "{{.State.Running}}") != "true" {
		if _, err := podmanOut("start", cname(m.Name)); err != nil {
			return err
		}
		if err := postStart(m, prof); err != nil {
			return err
		}
	}
	ex := []string{"exec", "-e", "PATH=" + prof + "/bin", "-w", "/root"}
	if len(cmd) == 0 {
		ex = append(ex, "-it", cname(m.Name), prof+"/bin/bash")
	} else {
		ex = append(ex, cname(m.Name))
		ex = append(ex, cmd...)
	}
	return podmanIO(ex...)
}

func ls() error {
	out, err := podmanOut("ps", "-a", "--filter", "label=spawn.name", "--format",
		`{{index .Labels "spawn.name"}}`+"\t"+`{{.State}}`+"\t"+`{{.RunningFor}}`+"\t"+`{{index .Labels "spawn.manifest"}}`)
	if err != nil {
		return err
	}
	if out == "" {
		fmt.Println("no envs. spawn up ./spawn.toml")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tAGE\tMANIFEST")
	fmt.Fprintln(w, out)
	return w.Flush()
}

func stop(name string) error {
	if inspect(name, "{{.Id}}") == "" {
		return fmt.Errorf("no env named %q", name)
	}
	_, err := podmanOut("stop", cname(name))
	return err
}

// rm destroys the container and the env's writable rootfs. Anything the env wrote and
// the manifest does not declare is gone, which is the point of a disposable env -- but
// say what is being deleted, because the manifest cannot bring it back.
func rm(name string) error {
	if inspect(name, "{{.Id}}") == "" && !dirExists(envDir(name)) {
		return fmt.Errorf("no env named %q", name)
	}
	if _, err := podmanOut("rm", "-f", cname(name)); err != nil {
		// A rootfs with no container is still worth cleaning up.
		fmt.Fprintln(os.Stderr, "spawn:", err)
	}
	d := envDir(name)
	fmt.Printf("removed env %s and its rootfs at %s\n", name, d)
	return os.RemoveAll(d)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
