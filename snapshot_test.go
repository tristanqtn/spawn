package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hashTree and diffEnv are the whole of `spawn diff`, and they are pure enough to
// test without a container.
func TestHashTreeAndDiff(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	const env = "difftest"
	root := rootfsDir(env)
	if err := os.MkdirAll(filepath.Join(root, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("root/seeded.txt", "from spawn")
	write("root/.bashrc", "generated")

	if err := writeBaseline(env, "/nix/store/p"); err != nil {
		t.Fatal(err)
	}

	// Nothing has happened yet, so nothing may be reported: a diff that cries wolf
	// about spawn's own seeded files is useless.
	ch, err := diffEnv(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 0 {
		t.Errorf("a freshly seeded env should show no changes, got %+v", ch)
	}

	write("root/agent-made-this.txt", "hello")
	write("root/seeded.txt", "modified by the agent")
	if err := os.Remove(filepath.Join(root, "root/.bashrc")); err != nil {
		t.Fatal(err)
	}

	ch, err = diffEnv(env)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range ch {
		got[c.Path] = c.Kind
	}
	want := map[string]string{
		"/root/agent-made-this.txt": "added",
		"/root/seeded.txt":          "modified",
		"/root/.bashrc":             "deleted",
	}
	for p, kind := range want {
		if got[p] != kind {
			t.Errorf("%s: got %q, want %q (all: %+v)", p, got[p], kind, got)
		}
	}
	if len(ch) != len(want) {
		t.Errorf("expected exactly %d changes, got %d: %+v", len(want), len(ch), ch)
	}

	// A modification that keeps the same size must still be caught, which is why the
	// baseline stores a hash and not just size and mtime.
	write("root/seeded.txt", "MODIFIED BY THE AGENT")
	ch, _ = diffEnv(env)
	found := false
	for _, c := range ch {
		if c.Path == "/root/seeded.txt" && c.Kind == "modified" {
			found = true
		}
	}
	if !found {
		t.Error("a same-length modification was missed")
	}
}

func TestDiffWithoutBaselineExplainsItself(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if _, err := diffEnv("nosuchenv"); err == nil {
		t.Error("diffing an env with no baseline should be an error")
	} else if !strings.Contains(err.Error(), "baseline") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

func TestCopyDirPreservesModesAndSymlinks(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "copy")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub/run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// An env's own symlink must survive a fork as a symlink, not be flattened.
	if err := os.Symlink("key", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "key")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("a 0600 file was copied as %o: a snapshot must not widen permissions", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Join(dst, "sub/run.sh")); err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Error("the executable bit was lost")
	}
	if fi, err := os.Lstat(filepath.Join(dst, "link")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was flattened into a regular file")
	}
}

func TestSnapshotTagValidation(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	const env = "tagtest"
	if err := os.MkdirAll(rootfsDir(env), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot(env, "../escape"); err == nil {
		t.Error("a tag with a path separator should be rejected")
	}
	if _, err := snapshot(env, "good"); err != nil {
		t.Fatal(err)
	}
	// Overwriting a snapshot silently would lose the thing it was taken to protect.
	if _, err := snapshot(env, "good"); err == nil {
		t.Error("re-using an existing tag should be refused")
	}
}

// M4's exit criterion: the Nth sandbox from one profile costs ~0 extra disk. The claim
// is worth asserting rather than assuming, because it is the entire economic argument
// for agent sandboxes -- and W0 measured that reuse ACROSS profiles is weak (10%), so
// only this same-profile case holds.
func TestNthEnvFromOneProfileIsNearlyFree(t *testing.T) {
	requireRuntime(t)

	src := "schema = 1\nname = \"%s\"\ntools = [\"nmap\", \"socat\"]\n"
	mk := func(name string) *Manifest {
		m, err := Parse([]byte(fmt.Sprintf(src, name)))
		if err != nil {
			t.Fatal(err)
		}
		rm(m.Name, true)
		t.Cleanup(func() { rm(m.Name, true) })
		if err := up(m, "/tmp/"+name+".toml", []string{"true"}); err != nil {
			t.Fatal(name, err)
		}
		return m
	}

	// Identical tool sets, different env names. The name only changes the buildEnv
	// derivation's name, so the underlying store paths are shared.
	a, b := mk("spawnnth1"), mk("spawnnth2")

	pa := inspect(a.Name, `{{index .Config.Labels "spawn.profile"}}`)
	pb := inspect(b.Name, `{{index .Config.Labels "spawn.profile"}}`)
	if pa == "" || pb == "" {
		t.Fatal("an env has no recorded profile")
	}

	// The expensive part -- the closure -- is the same store content for both. Compare
	// the closure size rather than the path, since the profile path includes the name.
	sizeOf := func(p string) int64 {
		out, err := nixCmd("path-info", "-S", "--json", p).Output()
		if err != nil {
			t.Skip("nix path-info unavailable:", err)
		}
		var recs []struct {
			ClosureSize int64 `json:"closureSize"`
		}
		if err := json.Unmarshal(out, &recs); err != nil || len(recs) == 0 {
			t.Skip("could not read closure size")
		}
		return recs[0].ClosureSize
	}
	if sa, sb := sizeOf(pa), sizeOf(pb); sa != sb {
		t.Errorf("two envs with the same tools have different closure sizes: %d vs %d", sa, sb)
	}

	// The per-env cost is the rootfs, and that is what "nearly free" means. A few
	// hundred KB is the expected order; anything near the closure's size would mean
	// something was copied that should have been shared.
	du := func(env string) int64 {
		var total int64
		filepath.Walk(rootfsDir(env), func(_ string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() {
				total += fi.Size()
			}
			return nil
		})
		return total
	}
	second := du(b.Name)
	const budget = 4 << 20 // 4 MiB
	if second > budget {
		t.Errorf("the second env's own files are %d bytes, over the %d budget: "+
			"the closure is not being shared", second, budget)
	}
	t.Logf("closure %d bytes shared; the second env's own files are %d bytes (%.4f%%)",
		sizeOf(pa), second, 100*float64(second)/float64(sizeOf(pa)))
}

// Snapshot, change, restore, fork: the lifecycle an agent uses to try something and
// put it back.
func TestSnapshotRestoreForkAgainstARealEnv(t *testing.T) {
	requireRuntime(t)

	m, err := Parse([]byte("schema = 1\nname = \"spawnsnaptest\"\ntools = [\"coreutils\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	rm(m.Name, true)
	t.Cleanup(func() {
		rm(m.Name, true)
		rm("spawnsnapfork", true)
	})
	if err := up(m, "/tmp/spawnsnap.toml", []string{"true"}); err != nil {
		t.Fatal(err)
	}

	if _, err := execIn(m.Name, "echo original > /root/work.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot(m.Name, "before"); err != nil {
		t.Fatal(err)
	}

	// Change it, and confirm diff reports exactly that.
	if _, err := execIn(m.Name, "echo ruined > /root/work.txt; echo junk > /root/junk.txt"); err != nil {
		t.Fatal(err)
	}
	ch, err := diffEnv(m.Name)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, c := range ch {
		kinds[c.Path] = c.Kind
	}
	if kinds["/root/work.txt"] != "added" && kinds["/root/work.txt"] != "modified" {
		t.Errorf("diff missed the changed file: %+v", ch)
	}
	if kinds["/root/junk.txt"] == "" {
		t.Errorf("diff missed a new file: %+v", ch)
	}

	if err := restore(m.Name, "before"); err != nil {
		t.Fatal(err)
	}
	if err := up(m, "/tmp/spawnsnap.toml", []string{"true"}); err != nil {
		t.Fatal("env did not come back after a restore:", err)
	}
	out, err := execIn(m.Name, "cat /root/work.txt; if [ -e /root/junk.txt ]; then echo JUNK-SURVIVED; fi; true")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "original") {
		t.Errorf("restore did not bring the file back: %q", out)
	}
	if strings.Contains(out, "JUNK-SURVIVED") {
		t.Error("restore left a file that was created after the snapshot")
	}

	// A fork inherits the filesystem and nothing else.
	if err := fork(m.Name, "spawnsnapfork"); err != nil {
		t.Fatal(err)
	}
	fm, err := Parse([]byte("schema = 1\nname = \"spawnsnapfork\"\ntools = [\"coreutils\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := up(fm, "/tmp/spawnsnapfork.toml", []string{"true"}); err != nil {
		t.Fatal(err)
	}
	out, err = execIn("spawnsnapfork", "cat /root/work.txt")
	if err != nil || !strings.Contains(out, "original") {
		t.Errorf("the fork did not inherit the filesystem: %q (%v)", out, err)
	}
}
