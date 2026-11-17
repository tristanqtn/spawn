package main

// spawn init: write a working manifest and a set of real dotfiles into a directory.
//
// This is the Exegol my-resources idea, except the resources are files in your own
// repository rather than a directory inside the image. You get a configured shell
// immediately, and every part of it is a file you can edit, diff and commit. Nothing
// here is special to spawn afterwards -- the manifest just references the dotfiles
// like any other manifest would.

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed templates
var templateFS embed.FS

// initKit writes the template tree into dir. It never overwrites without force,
// because the whole point is that these files become yours and get edited.
// engagement selects templates/engagement.toml as the manifest instead of the plain
// one: same dotfiles, but the pentest profile, the privileges scanning needs, a loot
// directory that survives a rebuild and a VPN block to fill in. It exists because the
// distance between "the tool works" and "I used it on real work" should be one command.
func initKit(dir string, force, engagement bool) error {
	if dir == "" {
		dir = "."
	}
	var written, skipped []string
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(p, "templates/")
		// Exactly one of the two manifest templates is written, as spawn.toml.
		switch rel {
		case "engagement.toml":
			if !engagement {
				return nil
			}
			rel = "spawn.toml"
		case "spawn.toml":
			if engagement {
				return nil
			}
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if _, err := os.Stat(dst); err == nil && !force {
			skipped = append(skipped, rel)
			return nil
		}
		b, err := templateFS.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return err
		}
		written = append(written, rel)
		return nil
	})
	if err != nil {
		return err
	}
	// The manifest mounts ./workspace and ./resources, and a missing mount source is
	// an error, so create them rather than leave the first `spawn up` to fail.
	// resources/README.md comes from the template tree, so that directory already
	// exists -- but only when the template was written, not when it was skipped.
	for _, d := range []string{"workspace", "resources"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return err
		}
	}

	t := newTable("", "FILE")
	for _, f := range written {
		t.add(ui.paint(ui.green, "new"), f)
	}
	for _, f := range skipped {
		t.add(ui.paint(ui.dim, "kept"), ui.paint(ui.dim, f+" (already there)"))
	}
	t.add(ui.paint(ui.green, "new"), "workspace/")
	t.add(ui.paint(ui.green, "new"), "resources/")
	t.print()

	if len(skipped) > 0 {
		fmt.Printf("\n%s\n", ui.paint(ui.dim,
			"Existing files were left alone. Use --force to overwrite them."))
	}
	fmt.Printf("\n%s\n", ui.paint(ui.bold, "Next:"))
	fmt.Println("  spawn check         # see what it resolves to, downloading nothing")
	fmt.Println("  spawn up            # build it and get a shell")
	fmt.Println()
	fmt.Println(ui.paint(ui.dim,
		"Then edit dotfiles/ and re-run spawn up. It applies to a running env,\n"+
			"so you can iterate on the prompt or tmux config without rebuilding."))
	return nil
}
