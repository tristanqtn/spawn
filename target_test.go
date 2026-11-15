package main

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// resolveTarget is the only place that decides what `spawn up X` means, so its
// precedence is worth pinning down: an explicit .toml, then an existing env, then
// the default manifest with everything treated as a command.
func TestResolveTargetPrecedence(t *testing.T) {
	cases := []struct {
		args []string
		want target
	}{
		{nil, target{manifest: "spawn.toml"}},
		{[]string{"lab.toml"}, target{manifest: "lab.toml"}},
		{[]string{"./d/lab.toml", "ls", "-l"}, target{manifest: "./d/lab.toml", cmd: []string{"ls", "-l"}}},
		// No env exists under `go test`, so a bare word is a command for the
		// default manifest rather than an env name.
		{[]string{"ls", "-l"}, target{manifest: "spawn.toml", cmd: []string{"ls", "-l"}}},
	}
	for _, c := range cases {
		got := resolveTarget(c.args)
		if got.manifest != c.want.manifest || got.env != c.want.env ||
			!reflect.DeepEqual(nonEmpty(got.cmd), nonEmpty(c.want.cmd)) {
			t.Errorf("resolveTarget(%v) = %+v, want %+v", c.args, got, c.want)
		}
	}
}

// A manifest path must win even when an env shares its name, because a path is
// unambiguous and the user typed it deliberately.
func TestManifestPathBeatsEnvName(t *testing.T) {
	got := resolveTarget([]string{"spawn.toml"})
	if got.env != "" {
		t.Errorf("a .toml argument should never be read as an env name: %+v", got)
	}
}

// envExists must not shell out for something that cannot be an env name, both
// because it is pointless and because the name reaches a container name.
func TestEnvExistsRejectsNonNames(t *testing.T) {
	for _, bad := range []string{"", "../escape", "a/b", "-flag", "has space"} {
		if envExists(bad) {
			t.Errorf("envExists(%q) should be false", bad)
		}
	}
}

// Attaching is the path that makes an env usable after its manifest is gone, so it
// needs the profile recorded on the container.
func TestAttachNeedsARecordedProfile(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not on PATH")
	}
	err := attach("spawn-nonexistent-env-xyz", nil)
	if err == nil {
		t.Fatal("attaching to a container that does not exist should fail")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("the error should explain what is missing, got: %v", err)
	}
}

func nonEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
