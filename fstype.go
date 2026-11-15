package main

// Which filesystem a path sits on. This matters because an env's rootfs cannot live on
// a Windows drive mounted into WSL: podman fails to start the container with
//
//   container create failed (no logs from conmon): conmon bytes "": readObjectStart...
//
// which names nothing the user did. drvfs and 9p do not carry the ownership and
// xattr semantics a container rootfs needs.

import (
	"os"
	"path/filepath"
	"strings"
)

// Filesystems a container rootfs cannot live on, mapped to why.
var unusableRootfsFS = map[string]string{
	"9p":         "a Windows drive mounted into WSL",
	"drvfs":      "a Windows drive mounted into WSL",
	"virtiofs":   "a host directory shared into the VM",
	"cifs":       "a network share",
	"nfs":        "a network share",
	"nfs4":       "a network share",
	"fuseblk":    "a FUSE-mounted volume, commonly NTFS",
	"exfat":      "a filesystem without POSIX ownership",
	"vfat":       "a filesystem without POSIX ownership",
	"msdos":      "a filesystem without POSIX ownership",
	"ntfs":       "a filesystem without POSIX ownership",
	"ntfs3":      "a filesystem without POSIX ownership",
	"fuse.sshfs": "a remote filesystem",
}

// fsTypeOf returns the filesystem type the given path sits on, or "" if it cannot be
// determined. It walks up to the nearest existing ancestor, so it works for a
// directory spawn has not created yet. /proc is parsed rather than calling statfs so
// this file stays portable.
func fsTypeOf(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	// The deepest existing ancestor is the one whose filesystem the new directory
	// will inherit.
	for {
		if _, err := os.Stat(abs); err == nil {
			break
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	abs = filepath.ToSlash(abs)

	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	best, bestType := "", ""
	for _, line := range strings.Split(string(b), "\n") {
		// mountinfo: id parent major:minor root MOUNTPOINT opts... - FSTYPE source...
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mp := unescapeMount(f[4])
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(f) {
			continue
		}
		if mp == "/" || abs == mp || strings.HasPrefix(abs, strings.TrimSuffix(mp, "/")+"/") {
			// Longest matching mount point wins: /mnt/c beats /.
			if len(mp) >= len(best) {
				best, bestType = mp, f[sep+1]
			}
		}
	}
	return bestType
}

// unescapeMount undoes the octal escaping mountinfo applies to spaces and tabs.
func unescapeMount(s string) string {
	for from, to := range map[string]string{`\040`: " ", `\011`: "\t", `\012`: "\n", `\134`: `\`} {
		s = strings.ReplaceAll(s, from, to)
	}
	return s
}

// checkRootfsFS reports why the env directory cannot hold a container rootfs, or "".
func checkRootfsFS() (fstype, why string) {
	fstype = fsTypeOf(dataDir())
	return fstype, unusableRootfsFS[fstype]
}
