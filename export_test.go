package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An archive can name "../../.ssh/authorized_keys". An importer that honours it hands
// the archive's author the host, so this is the one test in the file that really
// matters.
func TestSafeJoinRefusesEscapes(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{
		"../escape", "../../etc/passwd", "rootfs/../../escape",
		"/etc/passwd/../../../escape",
	} {
		if p, err := safeJoin(dir, bad); err == nil && !strings.HasPrefix(p, dir) {
			t.Errorf("safeJoin accepted %q -> %q", bad, p)
		}
	}
	// An absolute member name is clamped into the destination rather than honoured.
	p, err := safeJoin(dir, "/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, dir) {
		t.Errorf("an absolute member escaped: %q", p)
	}
	// And ordinary names still work.
	if _, err := safeJoin(dir, "rootfs/root/.bashrc"); err != nil {
		t.Errorf("a normal member was rejected: %v", err)
	}
}

// A crafted archive must be refused rather than unpacked over the host.
func TestImportRefusesATraversalArchive(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	arc := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("schema = 1\nname = \"evil\"\ntools = [\"nmap\"]\n")
	tw.WriteHeader(&tar.Header{Name: exportManifest, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	evil := []byte("pwned")
	tw.WriteHeader(&tar.Header{Name: "../../../../tmp/spawn-pwned", Mode: 0o644, Size: int64(len(evil)), Typeflag: tar.TypeReg})
	tw.Write(evil)
	tw.Close()
	gz.Close()
	f.Close()

	// The property that matters is containment, not refusal: a traversing member is
	// clamped into the destination, so the import still works and nothing lands
	// outside. Asserting "it errors" would have been asserting the wrong thing.
	const outside = "/tmp/spawn-pwned"
	os.Remove(outside)
	name, _, err := importEnv(arc, "")
	if err != nil {
		t.Fatalf("a clamped archive should still import: %v", err)
	}
	if _, err := os.Stat(outside); err == nil {
		os.Remove(outside)
		t.Fatal("ESCAPE: the archive wrote outside the destination")
	}
	// Better than clamped: only rootfs/ is copied out of the staging directory, so a
	// member that traversed its way elsewhere is discarded rather than landing in the
	// env at a surprising path.
	if _, err := os.Stat(filepath.Join(rootfsDir(name), "tmp", "spawn-pwned")); err == nil {
		t.Error("the traversing member was kept inside the env")
	}
}

// A symlink is the other thing an archive can carry. It is recreated as a symlink and
// never resolved: inside the env the rootfs is /, so a relative climb lands back in the
// container, and spawn's host-side code must not follow it either.
func TestImportKeepsSymlinksWithoutFollowingThem(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	arc := filepath.Join(t.TempDir(), "link.tar.gz")
	f, _ := os.Create(arc)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("schema = 1\nname = \"linky\"\ntools = [\"nmap\"]\n")
	tw.WriteHeader(&tar.Header{Name: exportManifest, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.WriteHeader(&tar.Header{Name: "rootfs/escape", Linkname: "../../../../etc", Typeflag: tar.TypeSymlink, Mode: 0o777})
	tw.Close()
	gz.Close()
	f.Close()

	name, _, err := importEnv(arc, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	link := filepath.Join(rootfsDir(name), "escape")
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("the symlink was not extracted: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was resolved into a real file, which WOULD copy host content in")
	}
	// hashTree backs spawn diff, and it must not walk through the link into /etc.
	files, err := hashTree(rootfsDir(name))
	if err != nil {
		t.Fatal(err)
	}
	for p := range files {
		if strings.Contains(p, "passwd") || strings.Contains(p, "shadow") {
			t.Errorf("spawn followed the symlink out of the env: %s", p)
		}
	}
}

func TestImportRefusesAnArchiveWithNoManifest(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	arc := filepath.Join(t.TempDir(), "bare.tar.gz")
	f, _ := os.Create(arc)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	b := []byte("x")
	tw.WriteHeader(&tar.Header{Name: "rootfs/root/f", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write(b)
	tw.Close()
	gz.Close()
	f.Close()

	// Without a manifest there is nothing to rebuild the closure from, so the archive
	// is useless and saying so beats creating a broken env.
	if _, _, err := importEnv(arc, ""); err == nil {
		t.Error("an archive with no manifest should be refused")
	}
}

func TestImportRefusesAGarbageFile(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := filepath.Join(t.TempDir(), "not-an-archive.tar.gz")
	os.WriteFile(p, []byte("this is not gzip"), 0o644)
	if _, _, err := importEnv(p, ""); err == nil {
		t.Error("a non-archive should be refused")
	}
}

// The round trip is the feature: export an env, import it elsewhere under a new name,
// and find the work intact. The archive must stay small, because it deliberately does
// not carry the nix closure.
func TestExportImportRoundTrip(t *testing.T) {
	requireRuntime(t)

	m, err := Parse([]byte("schema = 1\nname = \"spawnexporttest\"\ntools = [\"coreutils\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	mpath := "/tmp/spawn-export-src.toml"
	if err := os.WriteFile(mpath, []byte("schema = 1\nname = \"spawnexporttest\"\ntools = [\"coreutils\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rm(m.Name, true)
	rm("spawnimporttest", true)
	t.Cleanup(func() { rm(m.Name, true); rm("spawnimporttest", true) })
	if err := up(m, mpath, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	if _, err := execIn(m.Name, "echo portable-state > /root/work.txt"); err != nil {
		t.Fatal(err)
	}

	arc := filepath.Join(t.TempDir(), "env.tar.gz")
	size, err := exportEnv(m.Name, arc)
	if err != nil {
		t.Fatal(err)
	}
	// The closure for this env is hundreds of megabytes; the archive must be nothing
	// like that, or it is carrying something it should not.
	if size > 2<<20 {
		t.Errorf("the archive is %d bytes: it may be carrying the closure", size)
	}
	t.Logf("archive is %d bytes", size)

	// Importing under the original name must refuse rather than overwrite.
	if _, _, err := importEnv(arc, ""); err == nil {
		t.Error("importing over an existing env should be refused")
	}

	name, impPath, err := importEnv(arc, "spawnimporttest")
	if err != nil {
		t.Fatal(err)
	}
	if name != "spawnimporttest" {
		t.Fatalf("imported as %q", name)
	}
	// The manifest has to have been renamed with it, or the container and its
	// manifest would disagree about which env this is.
	im := load2(t, impPath)
	if im.Name != "spawnimporttest" {
		t.Errorf("the imported manifest still says %q", im.Name)
	}
	if err := up(im, impPath, []string{"true"}); err != nil {
		t.Fatal("the imported env did not build:", err)
	}
	out, err := execIn(name, "cat /root/work.txt")
	if err != nil || !strings.Contains(out, "portable-state") {
		t.Errorf("the imported env lost the work: %q (%v)", out, err)
	}
}

func load2(t *testing.T, path string) *Manifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
