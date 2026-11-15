package main

// spawn export / spawn import.
//
// An env is a manifest plus whatever the env wrote, and both are small, so an export
// is a gzipped tar of exactly those two things. What it deliberately does NOT contain
// is the nix closure: that is gigabytes, and the manifest already names the exact
// revision to rebuild it from, which is the whole point of pinning. So an export is
// portable to any host with nix, and tiny.
//
// Shipping the closure as well -- for a host with no nix at all -- is a different
// feature with a different mechanism (dockerTools.streamLayeredImage, measured in W1),
// and it belongs with the self-contained images in M7 rather than here.

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const exportManifest = "manifest.toml"
const exportMeta = "spawn-export.toml"

// exportEnv writes the env to a .tar.gz.
func exportEnv(env, dst string) (int64, error) {
	if !dirExists(rootfsDir(env)) {
		return 0, fmt.Errorf("no env named %q", env)
	}
	mpath := inspect(env, `{{index .Config.Labels "spawn.manifest"}}`)
	manifest, err := os.ReadFile(mpath)
	if err != nil {
		return 0, fmt.Errorf("cannot read the env's manifest at %s: %w; "+
			"an export without one could not be rebuilt", mpath, err)
	}

	f, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	add := func(name string, mode int64, body []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err := tw.Write(body)
		return err
	}
	if err := add(exportManifest, 0o644, manifest); err != nil {
		return 0, err
	}
	meta := fmt.Sprintf("env = %q\nprofile = %q\nspawn = %q\n",
		env, inspect(env, `{{index .Config.Labels "spawn.profile"}}`), version)
	if err := add(exportMeta, 0o644, []byte(meta)); err != nil {
		return 0, err
	}

	// The rootfs, which is only what the env itself wrote.
	root := rootfsDir(env)
	err = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		name := "rootfs/" + filepath.ToSlash(rel)
		switch {
		case fi.IsDir():
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: int64(fi.Mode().Perm()), Typeflag: tar.TypeDir})
		case fi.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return tw.WriteHeader(&tar.Header{Name: name, Linkname: link, Typeflag: tar.TypeSymlink, Mode: 0o777})
		case !fi.Mode().IsRegular():
			// Sockets and devices cannot travel and are not state worth keeping.
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: int64(fi.Mode().Perm()), Size: int64(len(b)), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		return 0, err
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// safeJoin resolves an archive member against a directory, refusing anything that
// would escape it. A tar can name "../../.ssh/authorized_keys", and an importer that
// honours it hands the archive's author the host.
func safeJoin(dir, name string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean("/" + name))
	target := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(clean, "/")))
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if absTarget != absDir && !strings.HasPrefix(absTarget, absDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive member %q escapes the destination", name)
	}
	return target, nil
}

// importEnv unpacks an export and returns the manifest path to build from.
func importEnv(src, name string) (string, string, error) {
	f, err := os.Open(src)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", "", fmt.Errorf("%s is not a spawn export: %w", src, err)
	}
	defer gz.Close()

	// Unpack to a staging directory first, so a bad archive cannot half-overwrite an
	// existing env.
	stage, err := os.MkdirTemp(filepath.Dir(dataDir()), "spawn-import-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(stage)

	var manifestBody, metaBody []byte
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
		}
		switch h.Name {
		case exportManifest:
			if manifestBody, err = io.ReadAll(tr); err != nil {
				return "", "", err
			}
			continue
		case exportMeta:
			if metaBody, err = io.ReadAll(tr); err != nil {
				return "", "", err
			}
			continue
		}
		target, err := safeJoin(stage, h.Name)
		if err != nil {
			return "", "", err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(h.Mode).Perm()|0o700); err != nil {
				return "", "", err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", "", err
			}
			// A symlink is recreated as-is and deliberately not resolved. It cannot
			// be an escape: inside the env the rootfs IS /, so a relative climb
			// lands back inside the container, and on the host spawn never follows
			// one -- copyDir recreates links and hashTree skips non-regular files.
			os.Remove(target)
			if err := os.Symlink(h.Linkname, target); err != nil {
				return "", "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", "", err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode).Perm())
			if err != nil {
				return "", "", err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return "", "", err
			}
			out.Close()
		}
	}
	if manifestBody == nil {
		return "", "", fmt.Errorf("%s contains no %s, so there is nothing to rebuild from", src, exportManifest)
	}

	m, err := Parse(manifestBody)
	if err != nil {
		return "", "", fmt.Errorf("the exported manifest does not parse: %w", err)
	}
	if name == "" {
		name = m.Name
	}
	if !attrRe.MatchString(name) {
		return "", "", fmt.Errorf("env name %q is not [A-Za-z0-9_.+-]", name)
	}
	if dirExists(envDir(name)) || inspect(name, "{{.Id}}") != "" {
		return "", "", fmt.Errorf("env %q already exists; pass a different name", name)
	}
	// The name in the manifest has to match the env it will be created as, or the
	// container and its manifest would disagree.
	if name != m.Name {
		manifestBody = []byte(strings.Replace(string(manifestBody),
			fmt.Sprintf("name = %q", m.Name), fmt.Sprintf("name = %q", name), 1))
		if m2, err := Parse(manifestBody); err != nil || m2.Name != name {
			return "", "", fmt.Errorf("could not rename the imported env to %q", name)
		}
	}

	if err := os.MkdirAll(envDir(name), 0o755); err != nil {
		return "", "", err
	}
	if src := filepath.Join(stage, "rootfs"); dirExists(src) {
		if err := copyDir(src, rootfsDir(name)); err != nil {
			return "", "", err
		}
	}
	mpath := filepath.Join(envDir(name), exportManifest)
	if err := os.WriteFile(mpath, manifestBody, 0o644); err != nil {
		return "", "", err
	}
	_ = metaBody // informational only; the manifest is what rebuilds the env
	return name, mpath, nil
}
