package main

// Secrets. The hard rule: a secret's plaintext must never reach the nix store, a
// container image, or spawn's own state. /nix/store is world-readable and permanent,
// so a secret that lands there is a security incident, not a bug.
//
// How that is kept: the manifest references a secret by PATH to an encrypted file.
// spawn decrypts it into a tmpfs directory owned by the user (mode 0700, files 0600)
// and bind-mounts that directory read-only at /run/secrets. Nothing about the
// plaintext is ever passed to nix, written to the env's rootfs, or stored in a label.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Where a decrypted secret is visible inside the env.
const secretsMount = "/run/secrets"

var secretNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

type secret struct {
	name string // the filename under /run/secrets
	kind string // file, age or sops
	path string // the encrypted source on the host
}

// parseSecret reads one "<kind>:<path>" entry. A bare path is an unencrypted file,
// which is honest about what it is rather than pretending to be a secret store.
func parseSecret(name, spec string) (secret, error) {
	if !secretNameRe.MatchString(name) {
		return secret{}, fmt.Errorf("secret name %q is not a plain filename", name)
	}
	kind, path := "file", spec
	if i := strings.Index(spec, ":"); i > 0 {
		if k := spec[:i]; k == "age" || k == "sops" || k == "file" {
			kind, path = k, spec[i+1:]
		}
	}
	if path == "" {
		return secret{}, fmt.Errorf("secret %q has no path", name)
	}
	return secret{name: name, kind: kind, path: path}, nil
}

func (m *Manifest) secretList() ([]secret, error) {
	out := make([]secret, 0, len(m.Secrets))
	for _, name := range sortedKeys(m.Secrets) {
		s, err := parseSecret(name, m.Secrets[name])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// secretsStage is the tmpfs directory holding decrypted secrets for one env. It must
// be memory-backed: staging plaintext on disk would defeat the point, and a disk
// fallback that nobody notices is worse than a clear refusal.
func secretsStage(name string) (string, error) {
	rd := os.Getenv("XDG_RUNTIME_DIR")
	if rd == "" {
		return "", fmt.Errorf("no XDG_RUNTIME_DIR, so there is no tmpfs to stage secrets in; " +
			"spawn will not write plaintext to disk")
	}
	fi, err := os.Stat(rd)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("XDG_RUNTIME_DIR %s is not a usable directory", rd)
	}
	return filepath.Join(rd, "spawn", name, "secrets"), nil
}

// decryptors are resolved from the SAME pinned nixpkgs as the env's tools, so spawn
// needs nothing installed on the host and the versions move only when the pin does.
func (m *Manifest) decryptor(kind string) (string, error) {
	attr := map[string]string{"age": "age", "sops": "sops"}[kind]
	if attr == "" {
		return "", fmt.Errorf("no decryptor for %q", kind)
	}
	out, err := nixCmd("build", "--impure", "--no-link", "--print-out-paths", "--expr",
		fmt.Sprintf(`(import (builtins.getFlake %q).outPath { system = %q; }).%s`,
			m.Nixpkgs, nixSystem(), attr)).Output()
	if err != nil {
		return "", fmt.Errorf("could not build %s from the pinned nixpkgs: %w", attr, err)
	}
	return strings.TrimSpace(string(out)) + "/bin/" + attr, nil
}

// ageIdentity is the private key age decrypts with.
func ageIdentity() (string, error) {
	if p := os.Getenv("SPAWN_AGE_IDENTITY"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// The sops convention, so one key works for both kinds.
	p := filepath.Join(home, ".config", "sops", "age", "keys.txt")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("no age identity at %s; set SPAWN_AGE_IDENTITY to point at one", p)
	}
	return p, nil
}

// stageSecrets decrypts every secret into the tmpfs stage and returns the podman
// flags that expose it. Returns no flags when the manifest declares no secrets, so
// an env without secrets gets no /run/secrets at all.
func (m *Manifest) stageSecrets(manifestDir string) ([]string, error) {
	secs, err := m.secretList()
	if err != nil {
		return nil, err
	}
	if len(secs) == 0 {
		return nil, nil
	}
	stage, err := secretsStage(m.Name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return nil, err
	}
	// Update the stage in place. Removing and recreating the directory would break
	// the bind-mount of any env already running against it -- the container keeps
	// the old inode and /run/secrets silently goes empty.
	declared := map[string]bool{}
	for _, s := range secs {
		declared[s.name] = true
	}
	stale, err := os.ReadDir(stage)
	if err != nil {
		return nil, err
	}
	for _, e := range stale {
		if !declared[e.Name()] {
			// A secret dropped from the manifest must stop being visible.
			if err := os.Remove(filepath.Join(stage, e.Name())); err != nil {
				return nil, err
			}
		}
	}

	for _, s := range secs {
		src, err := resolveHostPath(s.path, manifestDir)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(src); err != nil {
			return nil, fmt.Errorf("secret %q: %s does not exist", s.name, src)
		}
		plain, err := m.decrypt(s, src)
		if err != nil {
			return nil, err
		}
		// 0600 before the content lands, never after.
		if err := os.WriteFile(filepath.Join(stage, s.name), plain, 0o600); err != nil {
			return nil, err
		}
	}
	return []string{"-v", filepath.ToSlash(stage) + ":" + secretsMount + ":ro"}, nil
}

// decrypt returns a secret's plaintext. Errors never include the command's output,
// because a decryptor that fails mid-stream can put plaintext in its own error.
func (m *Manifest) decrypt(s secret, src string) ([]byte, error) {
	switch s.kind {
	case "file":
		return os.ReadFile(src)
	case "age":
		id, err := ageIdentity()
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", s.name, err)
		}
		bin, err := m.decryptor("age")
		if err != nil {
			return nil, err
		}
		out, err := runQuiet(bin, "--decrypt", "-i", id, src)
		if err != nil {
			return nil, fmt.Errorf("secret %q: age could not decrypt %s", s.name, src)
		}
		return out, nil
	case "sops":
		bin, err := m.decryptor("sops")
		if err != nil {
			return nil, err
		}
		out, err := runQuiet(bin, "--decrypt", src)
		if err != nil {
			return nil, fmt.Errorf("secret %q: sops could not decrypt %s", s.name, src)
		}
		return out, nil
	}
	return nil, fmt.Errorf("secret %q: unknown kind %q", s.name, s.kind)
}

// clearSecrets removes an env's staged plaintext. Called when the env stops, since
// the mount is only meaningful while it runs.
func clearSecrets(name string) {
	if stage, err := secretsStage(name); err == nil {
		os.RemoveAll(filepath.Dir(stage))
	}
}
