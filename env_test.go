package main

import (
	"os/exec"
	"testing"
)

// The lifecycle is the one piece of logic that only breaks against a real runtime:
// container reuse, the rootfs surviving a restart, and a changed manifest replacing
// the container without losing what the env wrote. Skips where podman or nix is absent.
func TestEnvLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("needs podman and a nix store")
	}
	for _, bin := range []string{"podman", "nix"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}

	const path = "/tmp/spawn-lifecycle-test.toml"
	parse := func(src string) *Manifest {
		m, err := Parse([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := parse("schema = 1\nname = \"spawnselftest\"\ntools = [\"nmap\"]")

	rm(m.Name, true) // a leftover env from a failed run would make this meaningless
	t.Cleanup(func() { rm(m.Name, true) })

	if err := up(m, path, []string{"bash", "-c", "echo kept > /root/marker"}); err != nil {
		t.Fatal("first up:", err)
	}
	if err := up(m, path, []string{"test", "-f", "/root/marker"}); err != nil {
		t.Fatal("rootfs did not survive a second up:", err)
	}
	if err := stop(m.Name); err != nil {
		t.Fatal("stop:", err)
	}
	if got := inspect(m.Name, "{{.State.Running}}"); got == "true" {
		t.Error("still running after stop")
	}
	if err := up(m, path, []string{"test", "-f", "/root/marker"}); err != nil {
		t.Fatal("up did not restart a stopped env with its data:", err)
	}

	// A changed manifest must replace the container and keep the rootfs.
	m2 := parse("schema = 1\nname = \"spawnselftest\"\ntools = [\"nmap\", \"jq\"]")
	if err := up(m2, path, []string{"bash", "-c", "jq --version >/dev/null && test -f /root/marker"}); err != nil {
		t.Fatal("recreate on manifest change lost data or the new tool:", err)
	}

	if err := rm(m.Name, true); err != nil {
		t.Fatal("rm:", err)
	}
	if inspect(m.Name, "{{.Id}}") != "" {
		t.Error("container still present after rm")
	}
	if dirExists(envDir(m.Name)) {
		t.Error("rootfs still present after rm")
	}
}

// M2's exit criterion: destroy an env, rebuild it from scratch, and lose nothing that
// was declared. Undeclared state is expected to be gone -- that is what disposable
// means -- so this asserts both halves.
func TestPersistSurvivesRmAndRebuild(t *testing.T) {
	if testing.Short() {
		t.Skip("needs podman and a nix store")
	}
	for _, bin := range []string{"podman", "nix"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}

	const path = "/tmp/spawn-persist-test.toml"
	m, err := Parse([]byte("schema = 1\nname = \"spawnpersisttest\"\ntools = [\"nmap\"]\n" +
		"persist = [\"/loot\"]"))
	if err != nil {
		t.Fatal(err)
	}
	rm(m.Name, true)
	t.Cleanup(func() { rm(m.Name, true) })

	if err := up(m, path, []string{"bash", "-c",
		"echo declared > /loot/keep.txt; echo undeclared > /root/throwaway.txt"}); err != nil {
		t.Fatal("first up:", err)
	}

	// Destroy the env completely, short of --purge.
	if err := rm(m.Name, false); err != nil {
		t.Fatal("rm:", err)
	}
	if dirExists(envDir(m.Name)) {
		t.Fatal("rootfs survived rm")
	}

	if err := up(m, path, []string{"test", "-f", "/loot/keep.txt"}); err != nil {
		t.Error("declared persist did not survive rm and rebuild:", err)
	}
	if err := up(m, path, []string{"test", "-f", "/root/throwaway.txt"}); err == nil {
		t.Error("undeclared state survived rm, so the env is not disposable")
	}

	// --purge is the explicit way to lose it.
	if err := rm(m.Name, true); err != nil {
		t.Fatal("purge:", err)
	}
	if dirExists(persistDir(m.Name)) {
		t.Error("persisted data survived --purge")
	}
}
