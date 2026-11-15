package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesValidationRejects(t *testing.T) {
	bad := map[string]string{
		"relative path":            `[files]` + "\n" + `".tmux.conf" = { content = "x" }`,
		"inside the store":         `[files]` + "\n" + `"/nix/store/x" = { content = "x" }`,
		"neither from nor content": `[files]` + "\n" + `"/root/.x" = { mode = "0644" }`,
		"both from and content": `[files]` + "\n" +
			`"/root/.x" = { from = "./a", content = "b" }`,
		"bad mode": `[files]` + "\n" + `"/root/.x" = { content = "y", mode = "rwx" }`,
		// A file under a persist directory or a mount target is shadowed by that
		// mount and would silently never appear.
		"shadowed by persist": "persist = [\"/loot\"]\n[files]\n\"/loot/.cfg\" = { content = \"x\" }",
		"shadowed by mount":   "mounts = [\"/tmp:/data\"]\n[files]\n\"/data/.cfg\" = { content = \"x\" }",
	}
	for why, field := range bad {
		src := "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n" + field + "\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}

	// The same path NOT under a mount is fine.
	okSrc := "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\npersist = [\"/loot\"]\n" +
		"[files]\n\"/root/.cfg\" = { content = \"x\" }\n"
	if _, err := Parse([]byte(okSrc)); err != nil {
		t.Errorf("rejected a valid declaration: %v", err)
	}
}

func TestFileModeDefaultsAndParses(t *testing.T) {
	if m, _ := (fileSpec{}).mode(); m != 0o644 {
		t.Errorf("default mode = %o, want 644", m)
	}
	// A secret-ish file needs a tight mode, so octal has to round-trip.
	if m, err := (fileSpec{Mode: "0600"}).mode(); err != nil || m != 0o600 {
		t.Errorf("mode 0600 = %o (%v)", m, err)
	}
	if _, err := (fileSpec{Mode: "999"}).mode(); err == nil {
		t.Error("999 is not valid octal")
	}
}

func TestWriteIfChanged(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "f")
	wrote, err := writeIfChanged(dst, []byte("a"), 0o644)
	if err != nil || !wrote {
		t.Fatalf("first write: %v %v", wrote, err)
	}
	// Identical content must not be rewritten: it keeps timestamps stable and stops
	// spawn claiming it seeded something when it did not.
	if wrote, _ := writeIfChanged(dst, []byte("a"), 0o644); wrote {
		t.Error("rewrote an identical file")
	}
	if wrote, _ := writeIfChanged(dst, []byte("b"), 0o644); !wrote {
		t.Error("did not write changed content")
	}
	// A mode change alone still counts, or a tightened mode would never be applied.
	if wrote, _ := writeIfChanged(dst, []byte("b"), 0o600); !wrote {
		t.Error("did not apply a changed mode")
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode not applied: %v", fi.Mode().Perm())
	}
}

func TestCopyTreeKeepsExecutableBitAndSkipsSymlinks(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "init.lua"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "hook.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A dotfiles tree often symlinks to the host's layout, which does not exist in
	// the env; copying one would create a dangling link.
	_ = os.Symlink("/nonexistent/on/the/host", filepath.Join(src, "link"))

	if _, err := copyTree(src, dst, 0o644); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "sub", "hook.sh")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm()&0o111 == 0 {
		t.Error("executable bit lost on a script in a config tree")
	}
	if _, err := os.Stat(filepath.Join(dst, "init.lua")); err != nil {
		t.Error("regular file not copied")
	}
	if _, err := os.Lstat(filepath.Join(dst, "link")); err == nil {
		t.Error("symlink was copied; it would dangle inside the env")
	}
}

// Without /etc/passwd, getpwuid() fails and zsh reports
// "can't drop privileges; failed to get user information for uid 0".
// There is no base image, so spawn is the only thing that can provide it.
func TestSeedBaseEtcProvidesIdentity(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	const prof = "/nix/store/fake-profile"
	if err := seedBaseEtc("etctest", prof); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(envDir("etctest"), "rootfs", "etc")
	for _, f := range []string{"passwd", "group", "nsswitch.conf", "shells"} {
		if _, err := os.Stat(filepath.Join(etc, f)); err != nil {
			t.Errorf("/etc/%s not seeded", f)
		}
	}
	passwd, err := os.ReadFile(filepath.Join(etc, "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(passwd), "root:x:0:0:") {
		t.Errorf("uid 0 has no entry:\n%s", passwd)
	}
	// /bin/bash does not exist in an env, so the shell must be the profile's.
	if !strings.Contains(string(passwd), prof+"/bin/bash") {
		t.Errorf("login shell is not the profile's bash:\n%s", passwd)
	}
	if ns, _ := os.ReadFile(filepath.Join(etc, "nsswitch.conf")); !strings.Contains(string(ns), "passwd: files") {
		t.Error("nsswitch.conf does not resolve users from files")
	}
}
