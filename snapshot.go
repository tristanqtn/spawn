package main

// Snapshots, forks and diffs.
//
// W0 planned to use `podman commit`. That turns out to be impossible here:
//
//   Error: cannot commit a container that uses an exploded rootfs
//
// which is a direct consequence of having no base image. The replacement is better
// than the plan. Because /nix is mounted rather than copied, an env's rootfs holds
// only what the env itself wrote -- a couple of hundred kilobytes, not a gigabyte --
// so a snapshot is a directory copy, a fork is a directory copy, and a diff can
// afford to hash every file in the tree.
//
// This is also what makes the Nth sandbox from a profile nearly free: the closure is
// shared and immutable, and the per-env part is tiny.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const baselineFile = "baseline.json"

// fileState is one file's identity in a baseline. Size is kept alongside the hash
// because it makes a diff readable ("grew by 4KB") without re-reading anything.
type fileState struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

type baseline struct {
	Taken   time.Time            `json:"taken"`
	Profile string               `json:"profile"`
	Files   map[string]fileState `json:"files"`
}

func snapshotsDir(env string) string { return filepath.Join(envDir(env), "snapshots") }
func rootfsDir(env string) string    { return filepath.Join(envDir(env), "rootfs") }

// hashTree records every file under root, keyed by its path inside the env.
func hashTree(root string) (map[string]fileState, error) {
	out := map[string]fileState{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			// A file that vanished mid-walk is not worth failing over; a running env
			// is allowed to be busy.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if fi.IsDir() || !fi.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		h, err := hashFile(p)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return err
		}
		out["/"+filepath.ToSlash(rel)] = fileState{Hash: h, Size: fi.Size(), Mode: uint32(fi.Mode().Perm())}
		return nil
	})
	return out, err
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeBaseline records the env's contents as they are now. It runs after seeding, so
// the files spawn itself put there are part of the baseline and never show up as
// something the env changed.
func writeBaseline(env, prof string) error {
	files, err := hashTree(rootfsDir(env))
	if err != nil {
		return err
	}
	b, err := json.Marshal(baseline{Taken: time.Now().UTC(), Profile: prof, Files: files})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(envDir(env), baselineFile), b, 0o600)
}

func readBaseline(env string) (*baseline, error) {
	b, err := os.ReadFile(filepath.Join(envDir(env), baselineFile))
	if err != nil {
		return nil, err
	}
	var bl baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}

type change struct {
	Path string
	Kind string // added, modified, deleted
	Size int64
}

// diffEnv compares the env's current contents against its baseline.
func diffEnv(env string) ([]change, error) {
	bl, err := readBaseline(env)
	if err != nil {
		return nil, fmt.Errorf("no baseline for %q: it was created before diffs existed, "+
			"or by another spawn. Re-create the env to get one", env)
	}
	now, err := hashTree(rootfsDir(env))
	if err != nil {
		return nil, err
	}
	var out []change
	for p, cur := range now {
		old, ok := bl.Files[p]
		switch {
		case !ok:
			out = append(out, change{p, "added", cur.Size})
		case old.Hash != cur.Hash:
			out = append(out, change{p, "modified", cur.Size})
		}
	}
	for p, old := range bl.Files {
		if _, ok := now[p]; !ok {
			out = append(out, change{p, "deleted", old.Size})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// copyDir copies a tree, preserving permissions. Symlinks are recreated rather than
// followed, so an env's own links survive a fork without being flattened.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, fi.Mode().Perm()|0o700)
		case fi.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			os.Remove(target)
			return os.Symlink(link, target)
		case !fi.Mode().IsRegular():
			// Sockets and devices cannot be copied and do not belong in a snapshot.
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

var snapNameRe = attrRe

// snapshot copies the env's rootfs aside under a tag.
func snapshot(env, tag string) (string, error) {
	if inspect(env, "{{.Id}}") == "" && !dirExists(rootfsDir(env)) {
		return "", fmt.Errorf("no env named %q", env)
	}
	if tag == "" {
		tag = time.Now().UTC().Format("20060102-150405")
	}
	if !snapNameRe.MatchString(tag) {
		return "", fmt.Errorf("snapshot tag %q is not a plain name", tag)
	}
	dst := filepath.Join(snapshotsDir(env), tag)
	if dirExists(dst) {
		return "", fmt.Errorf("snapshot %q already exists; remove it or pick another tag", tag)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	if err := copyDir(rootfsDir(env), filepath.Join(dst, "rootfs")); err != nil {
		return "", err
	}
	// The profile is part of the snapshot: restoring a rootfs under a different
	// closure would be a different env wearing its clothes.
	prof := inspect(env, `{{index .Config.Labels "spawn.profile"}}`)
	meta := fmt.Sprintf("profile = %q\ntaken = %q\n", prof, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dst, "meta.toml"), []byte(meta), 0o644); err != nil {
		return "", err
	}
	return dst, nil
}

func listSnapshots(env string) ([]string, error) {
	es, err := os.ReadDir(snapshotsDir(env))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range es {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// restore replaces the env's rootfs with a snapshot. The container is removed first:
// swapping the filesystem under a running container would leave it holding deleted
// inodes, which is the same mistake that once made `spawn rm` destructive.
func restore(env, tag string) error {
	src := filepath.Join(snapshotsDir(env), tag, "rootfs")
	if !dirExists(src) {
		have, _ := listSnapshots(env)
		return fmt.Errorf("no snapshot %q for %q (have: %s)", tag, env, strings.Join(have, ", "))
	}
	if inspect(env, "{{.Id}}") != "" {
		if _, err := podmanOut("rm", "-f", cname(env)); err != nil {
			return err
		}
	}
	live := rootfsDir(env)
	old := live + ".replacing"
	if err := os.RemoveAll(old); err != nil {
		return err
	}
	if err := os.Rename(live, old); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := copyDir(src, live); err != nil {
		// Put the env back rather than leave it with no rootfs at all.
		os.RemoveAll(live)
		os.Rename(old, live)
		return err
	}
	return os.RemoveAll(old)
}

// fork copies an env into a new one. It is commit-then-start, never live migration:
// CRIU is unavailable on the WSL2 kernel, so a running process cannot be moved. The
// fork starts fresh with the filesystem it inherited.
func fork(env, newName string) error {
	if !attrRe.MatchString(newName) {
		return fmt.Errorf("env name %q is not [A-Za-z0-9_.+-]", newName)
	}
	if !dirExists(rootfsDir(env)) {
		return fmt.Errorf("no env named %q", env)
	}
	if dirExists(envDir(newName)) || inspect(newName, "{{.Id}}") != "" {
		return fmt.Errorf("env %q already exists", newName)
	}
	if err := os.MkdirAll(envDir(newName), 0o755); err != nil {
		return err
	}
	if err := copyDir(rootfsDir(env), rootfsDir(newName)); err != nil {
		return err
	}
	// The baseline travels with the fork, so `spawn diff` on the fork still reports
	// changes relative to the original env's starting point.
	if b, err := os.ReadFile(filepath.Join(envDir(env), baselineFile)); err == nil {
		os.WriteFile(filepath.Join(envDir(newName), baselineFile), b, 0o600)
	}
	return nil
}
