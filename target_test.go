package main

import (
	"os"
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

// attach is the path taken when an env's manifest is gone, and the quick way into a
// box: no nix build at all. It has to use the SHELL the manifest chose, which is why
// that is recorded as a label.
func TestAttachRunsWithoutTheManifest(t *testing.T) {
	requireRuntime(t)

	m, err := Parse([]byte("schema = 1\nname = \"spawnattachtest\"\ntools = [\"coreutils\"]\n" +
		"[shell]\nuse = \"zsh\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	path := "/tmp/spawn-attach-test.toml"
	if err := os.WriteFile(path, []byte("schema = 1\nname = \"spawnattachtest\"\ntools = [\"coreutils\"]\n"+
		"[shell]\nuse = \"zsh\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rm(m.Name, true)
	t.Cleanup(func() { rm(m.Name, true); os.Remove(path) })
	if err := up(m, path, []string{"true"}); err != nil {
		t.Fatal(err)
	}

	// The recorded shell is the declared one, not a silent fallback to bash.
	if sh := inspect(m.Name, `{{index .Config.Labels "spawn.shell"}}`); !strings.HasSuffix(sh, "/bin/zsh") {
		t.Errorf("recorded shell is %q, want the profile's zsh", sh)
	}

	// Delete the manifest: resolveTarget must still find the env by name, and
	// upTarget must fall back to attaching rather than refusing.
	os.Remove(path)
	tg := resolveTarget([]string{m.Name, "true"})
	if tg.env != m.Name {
		t.Fatalf("resolveTarget did not recognise the env: %+v", tg)
	}
	if err := upTarget(tg); err != nil {
		t.Fatal("attaching to an env whose manifest is gone failed:", err)
	}

	// Attach also has to start a STOPPED env, or `spawn up <name>` would do nothing
	// useful after a reboot.
	if err := stop(m.Name); err != nil {
		t.Fatal(err)
	}
	if err := attach(m.Name, []string{"true"}); err != nil {
		t.Fatal("attach did not start a stopped env:", err)
	}
	if inspect(m.Name, "{{.State.Running}}") != "true" {
		t.Error("the env is not running after attach")
	}
}
