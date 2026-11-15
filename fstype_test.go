package main

import "testing"

func TestFsTypeOf(t *testing.T) {
	// A path that certainly exists, on a filesystem that certainly works.
	if got := fsTypeOf("/proc"); got != "proc" {
		t.Errorf("fsTypeOf(/proc) = %q, want proc", got)
	}
	// The deepest existing ancestor decides, so a path spawn has not created yet
	// still resolves.
	if got := fsTypeOf("/proc/does/not/exist/yet"); got != "proc" {
		t.Errorf("fsTypeOf of a missing path under /proc = %q, want proc", got)
	}
	// Longest-prefix matching: this must not fall back to the root filesystem.
	if fsTypeOf("/") == "" {
		t.Error("fsTypeOf(/) returned nothing")
	}
}

func TestUnusableRootfsFS(t *testing.T) {
	// drvfs and 9p are how a Windows drive appears inside WSL, and both produce an
	// unreadable conmon error if an env rootfs is put there.
	for _, fs := range []string{"drvfs", "9p"} {
		if unusableRootfsFS[fs] == "" {
			t.Errorf("%s should be rejected as rootfs storage", fs)
		}
	}
	for _, fs := range []string{"ext4", "btrfs", "xfs", "zfs", "tmpfs", "overlay"} {
		if unusableRootfsFS[fs] != "" {
			t.Errorf("%s should be acceptable rootfs storage", fs)
		}
	}
}
