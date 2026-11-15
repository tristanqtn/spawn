package main

// Working out what `spawn up X` means.
//
// X is a manifest path or the name of an existing env. Re-entering a box you already
// built should not require knowing where its manifest lives, and the container
// already records that: the spawn.manifest label. So `spawn up lab` finds the
// manifest, rebuilds if it changed, and drops you in -- from any directory.
//
// If the manifest has moved or been deleted, the env is still there and still useful,
// so spawn attaches to it using the profile recorded on the container instead of
// refusing.

import (
	"fmt"
	"os"
	"strings"
)

type target struct {
	manifest string   // path to a manifest, when there is one
	env      string   // an existing env name, when X named one
	cmd      []string // what to run inside
}

// resolveTarget interprets the arguments to `spawn up`.
//
// Precedence: an explicit .toml path, then the name of an existing env, then the
// default ./spawn.toml with everything treated as a command. An env name and a
// command name can in principle collide -- `spawn up bash` with an env called bash
// enters that env rather than running bash in the default one -- which is why the
// env name wins only when an env by that name actually exists.
func resolveTarget(args []string) target {
	if len(args) > 0 && strings.HasSuffix(args[0], ".toml") {
		return target{manifest: args[0], cmd: args[1:]}
	}
	if len(args) > 0 && envExists(args[0]) {
		return target{env: args[0], cmd: args[1:]}
	}
	return target{manifest: "spawn.toml", cmd: args}
}

func envExists(name string) bool {
	if !attrRe.MatchString(name) {
		return false
	}
	return inspect(name, "{{.Id}}") != ""
}

// attach enters an existing env without its manifest. The container records the
// profile it was built from, so this needs no nix build at all -- which also makes it
// the fast path for "give me a shell in the box I already have".
func attach(name string, cmd []string) error {
	prof := inspect(name, `{{index .Config.Labels "spawn.profile"}}`)
	if prof == "" {
		return fmt.Errorf("env %q has no recorded profile; it was not created by this spawn", name)
	}
	shell := inspect(name, `{{index .Config.Labels "spawn.shell"}}`)
	if shell == "" {
		shell = prof + "/bin/bash"
	}
	if inspect(name, "{{.State.Running}}") != "true" {
		if _, err := podmanOut("start", cname(name)); err != nil {
			return err
		}
	}
	ex := []string{"exec", "-e", "PATH=" + prof + "/bin", "-w", "/root"}
	if len(cmd) == 0 {
		ex = append(ex, "-it", cname(name), shell)
	} else {
		ex = append(ex, "-i", cname(name))
		ex = append(ex, cmd...)
	}
	return podmanIO(ex...)
}

// upTarget runs `spawn up` for a resolved target.
func upTarget(t target) error {
	if t.env == "" {
		return up(load(t.manifest), absPath(t.manifest), t.cmd)
	}
	// Named an existing env: prefer its manifest so the env still matches what was
	// declared, and fall back to attaching when the manifest is gone.
	mpath := inspect(t.env, `{{index .Config.Labels "spawn.manifest"}}`)
	if mpath == "" {
		return attach(t.env, t.cmd)
	}
	if _, err := os.Stat(mpath); err != nil {
		fmt.Fprintf(os.Stderr, "spawn: %s is gone, attaching to the existing env instead\n", mpath)
		return attach(t.env, t.cmd)
	}
	b, err := os.ReadFile(mpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spawn: cannot read %s, attaching to the existing env instead\n", mpath)
		return attach(t.env, t.cmd)
	}
	m, err := Parse(b)
	if err != nil {
		// A manifest edited into an invalid state should not strand the user outside
		// a box that is running right now.
		fmt.Fprintf(os.Stderr, "spawn: %s: %s\n       attaching to the existing env instead\n", mpath, err)
		return attach(t.env, t.cmd)
	}
	if m.Name != t.env {
		return fmt.Errorf("%s declares name = %q, but it is recorded as env %q; "+
			"run spawn rm %s or fix the manifest", mpath, m.Name, t.env, t.env)
	}
	return up(m, mpath, t.cmd)
}
