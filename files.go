package main

// Declared config files.
//
// `mounts` already puts a host dotfile in an env, but a bind mount is the wrong tool
// for configuration: it is read-only and lives outside the env, so any tool that
// rewrites its own config fails. neovim writes lazy-lock.json beside init.lua, gh
// writes hosts.yml, bat builds a cache. Those need a real, writable file.
//
// So `files` COPIES instead. The trick that makes this cheap: --rootfs is a plain
// host directory, so seeding a file into the env is ordinary file copying. No podman
// involvement, and it works whether or not the env is running.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// fileSpec is one declared file or directory. Exactly one of From and Content is set.
type fileSpec struct {
	From    string `toml:"from"`    // a host path, file or directory
	Content string `toml:"content"` // literal content, for short config
	Mode    string `toml:"mode"`    // octal, e.g. "0600" for a key
}

func (f fileSpec) mode() (os.FileMode, error) {
	if f.Mode == "" {
		return 0o644, nil
	}
	n, err := strconv.ParseUint(f.Mode, 8, 32)
	if err != nil || n > 0o7777 {
		return 0, fmt.Errorf("mode %q is not octal, e.g. \"0600\"", f.Mode)
	}
	return os.FileMode(n), nil
}

func (m *Manifest) validateFiles() error {
	for path, spec := range m.Files {
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("files: %q must be an absolute path inside the env", path)
		}
		clean := filepath.ToSlash(filepath.Clean(path))
		if strings.HasPrefix(clean, "/nix/") || clean == "/nix" {
			return fmt.Errorf("files: %q is inside the read-only shared store", path)
		}
		if (spec.From == "") == (spec.Content == "") {
			return fmt.Errorf("files: %q needs exactly one of from or content", path)
		}
		if _, err := spec.mode(); err != nil {
			return fmt.Errorf("files: %q: %w", path, err)
		}
		// A file under a persist directory or a mount target is shadowed by that
		// mount and would silently never appear. Catch it here rather than let the
		// user wonder why their config is missing.
		if owner := m.shadowedBy(clean); owner != "" {
			return fmt.Errorf("files: %q is inside %q, which is mounted over it; "+
				"put the file in the mounted directory on the host instead", path, owner)
		}
	}
	return nil
}

// shadowedBy returns the persist entry or mount target that would hide path.
func (m *Manifest) shadowedBy(path string) string {
	under := func(dir string) bool {
		dir = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(dir)), "/")
		return dir != "" && (path == dir || strings.HasPrefix(path, dir+"/"))
	}
	for _, p := range m.Persist {
		if under(p) {
			return p
		}
	}
	for _, spec := range m.Mounts {
		_, rest, err := splitMount(spec)
		if err != nil {
			continue
		}
		if target := strings.SplitN(rest, ":", 2)[0]; under(target) {
			return target
		}
	}
	return ""
}

// envRootfsPath maps a path inside the env to its real location on the host. This
// works because --rootfs is a plain directory, which is what makes seeding files as
// cheap as copying them.
func envRootfsPath(name, inside string) string {
	rel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(inside)), "/")
	return filepath.Join(envDir(name), "rootfs", filepath.FromSlash(rel))
}

// seedBaseEtc writes the identity files glibc expects. There is no base image, so
// nothing else provides them, and without /etc/passwd any getpwuid() call fails:
//
//	zsh: can't drop privileges; failed to get user information for uid 0
//
// ssh refuses to run, tmux cannot find a login shell, and git cannot guess an author.
// The login shell is the one [shell] chose, resolved in the profile, since /bin/bash
// does not exist either; that is why this is rewritten on every up rather than only
// at create.
//
// A manifest may override any of these by declaring it in files, because the user's
// declaration is seeded afterwards and wins.
func seedBaseEtc(name, loginShell, prof string) error {
	etc := filepath.Join(envDir(name), "rootfs", "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return err
	}
	base := map[string]string{
		"passwd": "root:x:0:0:root:/root:" + loginShell + "\n" +
			"nobody:x:65534:65534:nobody:/:/sbin/nologin\n",
		"group": "root:x:0:\nnogroup:x:65534:\n",
		// glibc needs this to resolve users from files at all.
		"nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n",
		"shells":        loginShell + "\n",
	}
	for f, content := range base {
		if _, err := writeIfChanged(filepath.Join(etc, f), []byte(content), 0o644); err != nil {
			return fmt.Errorf("seeding /etc/%s: %w", f, err)
		}
	}
	// Local time. Without this an env is UTC, and a prompt that shows a clock is
	// quietly wrong by an hour or more.
	if tz := hostLocaltime(); tz != nil {
		if _, err := writeIfChanged(filepath.Join(etc, "localtime"), tz, 0o644); err != nil {
			return fmt.Errorf("seeding /etc/localtime: %w", err)
		}
	}
	if name := hostTimezone(); name != "" {
		if _, err := writeIfChanged(filepath.Join(etc, "timezone"), []byte(name+"\n"), 0o644); err != nil {
			return fmt.Errorf("seeding /etc/timezone: %w", err)
		}
	}
	// protocols and services, taken from iana-etc in the profile rather than from the
	// host, so two hosts seed byte-identical files.
	//
	// Without /etc/protocols, getprotobyname("icmp") fails and fping exits with
	// "fping: icmp: unknown protocol" -- an error naming neither the container nor
	// the missing file. Anything resolving a protocol or service by name hits the
	// same wall, which is most of recon. Found by a smoke check, not by reasoning.
	for _, f := range []string{"protocols", "services"} {
		b, err := os.ReadFile(filepath.Join(prof, "etc", f))
		if err != nil {
			// iana-etc is in baseTools, so this should not happen. An env that
			// somehow lacks it still works, just without name lookups.
			continue
		}
		if _, err := writeIfChanged(filepath.Join(etc, f), b, 0o644); err != nil {
			return fmt.Errorf("seeding /etc/%s: %w", f, err)
		}
	}
	return nil
}

// seedFiles writes every declared file into the env's rootfs. It runs on every `up`,
// so editing a host dotfile and re-running applies it -- including to a running env,
// since the rootfs directory IS the container's filesystem.
//
// Declared files are authoritative and overwritten. That is the point of declaring
// them: if you want a file spawn does not manage, do not declare it.
func (m *Manifest) seedFiles(manifestDir string) error {
	if len(m.Files) == 0 {
		return nil
	}
	changed := 0
	for _, path := range sortedFileKeys(m.Files) {
		spec := m.Files[path]
		mode, err := spec.mode()
		if err != nil {
			return err
		}
		dst := envRootfsPath(m.Name, path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}

		if spec.Content != "" {
			wrote, err := writeIfChanged(dst, []byte(spec.Content), mode)
			if err != nil {
				return fmt.Errorf("files: %q: %w", path, err)
			}
			if wrote {
				changed++
			}
			continue
		}

		src, err := resolveHostPath(spec.From, manifestDir)
		if err != nil {
			return err
		}
		fi, err := os.Stat(src)
		if err != nil {
			return fmt.Errorf("files: %q: %s does not exist", path, src)
		}
		if fi.IsDir() {
			n, err := copyTree(src, dst, mode)
			if err != nil {
				return fmt.Errorf("files: %q: %w", path, err)
			}
			changed += n
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		wrote, err := writeIfChanged(dst, b, mode)
		if err != nil {
			return fmt.Errorf("files: %q: %w", path, err)
		}
		if wrote {
			changed++
		}
	}
	if changed > 0 {
		fmt.Fprintf(os.Stderr, "spawn: seeded %d declared file(s)\n", changed)
	}
	return nil
}

// writeIfChanged avoids rewriting an identical file, so timestamps stay stable and
// the "seeded N files" line only appears when something actually changed.
func writeIfChanged(dst string, content []byte, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(dst); err == nil && string(old) == string(content) {
		if fi, err := os.Stat(dst); err == nil && fi.Mode().Perm() == mode.Perm() {
			return false, nil
		}
	}
	if err := os.WriteFile(dst, content, mode); err != nil {
		return false, err
	}
	// WriteFile only applies mode when creating, so set it explicitly.
	return true, os.Chmod(dst, mode)
}

// copyTree copies a directory recursively, for a config directory such as
// ~/.config/nvim. Directories get the executable bit so they can be entered.
func copyTree(src, dst string, mode os.FileMode) (int, error) {
	changed := 0
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !fi.Mode().IsRegular() {
			// Symlinks in a dotfiles tree usually point at the host's layout, which
			// does not exist in the env; copying them would create dangling links.
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// Preserve the executable bit for scripts in a config tree.
		fmode := mode
		if fi.Mode().Perm()&0o111 != 0 {
			fmode = mode | 0o111
		}
		wrote, err := writeIfChanged(target, b, fmode)
		if wrote {
			changed++
		}
		return err
	})
	return changed, err
}

func sortedFileKeys(m map[string]fileSpec) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
