package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSecretSpecs(t *testing.T) {
	for spec, want := range map[string]secret{
		"/x/y.ovpn":           {name: "s", kind: "file", path: "/x/y.ovpn"},
		"file:/x/y":           {name: "s", kind: "file", path: "/x/y"},
		"age:~/k/t.age":       {name: "s", kind: "age", path: "~/k/t.age"},
		"sops:./secrets.yaml": {name: "s", kind: "sops", path: "./secrets.yaml"},
	} {
		got, err := parseSecret("s", spec)
		if err != nil {
			t.Errorf("%s: %v", spec, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %+v want %+v", spec, got, want)
		}
	}
	for _, bad := range []string{"", "age:", "file:"} {
		if _, err := parseSecret("s", bad); err == nil {
			t.Errorf("accepted empty path: %q", bad)
		}
	}
	// The name becomes a filename under /run/secrets, so it cannot contain a path.
	for _, bad := range []string{"../escape", "a/b", ".hidden", ""} {
		if _, err := parseSecret(bad, "/x"); err == nil {
			t.Errorf("accepted bad secret name %q", bad)
		}
	}
}

// M2's exit criterion, and the one that matters most: a secret is consumed by a
// running env and appears NOWHERE in the nix store, spawn's own state, or the
// container's metadata. /nix/store is world-readable and permanent, so a leak there
// is not a bug to fix later.
func TestSecretReachesEnvButLeaksNowhere(t *testing.T) {
	if testing.Short() {
		t.Skip("needs podman and a nix store")
	}
	for _, bin := range []string{"podman", "nix"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}

	// A value distinctive enough that finding it anywhere is unambiguous.
	const canary = "spawn-canary-6f2b9d4e-do-not-leak"
	dir := t.TempDir()

	// Encrypt it for real: a plaintext file would not exercise the decrypt path.
	keyFile := filepath.Join(dir, "age.key")
	ageBin, err := (&Manifest{Nixpkgs: defaultNixpkgs}).decryptor("age")
	if err != nil {
		t.Skip("age unavailable from the pinned nixpkgs:", err)
	}
	keygen := filepath.Join(filepath.Dir(ageBin), "age-keygen")
	key, err := exec.Command(keygen).Output()
	if err != nil {
		t.Fatal("age-keygen:", err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	var recipient string
	for _, line := range strings.Split(string(key), "\n") {
		if strings.HasPrefix(line, "# public key: ") {
			recipient = strings.TrimPrefix(line, "# public key: ")
		}
	}
	if recipient == "" {
		t.Fatal("no recipient in generated key")
	}
	encrypted := filepath.Join(dir, "token.age")
	enc := exec.Command(ageBin, "--encrypt", "-r", recipient, "-o", encrypted)
	enc.Stdin = strings.NewReader(canary)
	if out, err := enc.CombinedOutput(); err != nil {
		t.Fatal("age encrypt:", err, string(out))
	}
	t.Setenv("SPAWN_AGE_IDENTITY", keyFile)

	manifest := filepath.Join(dir, "spawn.toml")
	m, err := Parse([]byte("schema = 1\nname = \"spawnsecrettest\"\ntools = [\"nmap\"]\n" +
		"[secrets]\ntoken = \"age:./token.age\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	rm(m.Name, true)
	t.Cleanup(func() { rm(m.Name, true) })

	// 1. The env can actually read it.
	out, err := podmanOutAfterUp(t, m, manifest, []string{"cat", "/run/secrets/token"})
	if err != nil {
		t.Fatal("env could not read the secret:", err)
	}
	if strings.TrimSpace(out) != canary {
		t.Fatalf("secret did not arrive intact: %q", strings.TrimSpace(out))
	}

	// 2. It is read-only inside, and re-running up does not disturb the live mount.
	// Asserting on the message matters: an empty /run/secrets also fails the write,
	// but for the wrong reason, and that is exactly the bug this caught once.
	wr, _ := podmanOut("exec", cname(m.Name), "bash", "-c",
		"if echo x > /run/secrets/token 2>/dev/null; then echo WRITABLE; else echo readonly; fi")
	if strings.TrimSpace(wr) != "readonly" {
		t.Errorf("secret mount should be read-only, got %q", strings.TrimSpace(wr))
	}
	again, err := podmanOutAfterUp(t, m, manifest, []string{"cat", "/run/secrets/token"})
	if err != nil || strings.TrimSpace(again) != canary {
		t.Errorf("secret did not survive a second up: %q (%v)", strings.TrimSpace(again), err)
	}

	// 3. It is nowhere in the nix store.
	if grepTree(t, "/nix/store/"+filepath.Base(storePathOf(t, m)), canary) {
		t.Error("LEAK: the secret is in the env's nix closure")
	}
	if hits, _ := exec.Command("grep", "-rl", canary, "/nix/store").Output(); len(hits) > 0 {
		t.Errorf("LEAK: the secret is in /nix/store: %s", hits)
	}

	// 4. It is nowhere in spawn's own state: not the rootfs, not persisted data.
	if grepTree(t, dataDir(), canary) {
		t.Error("LEAK: the secret is in spawn's state directory")
	}

	// 5. It is not in the container's metadata, which podman stores on disk.
	meta, _ := exec.Command("podman", "inspect", cname(m.Name)).Output()
	if strings.Contains(string(meta), canary) {
		t.Error("LEAK: the secret is in the container's metadata")
	}

	// 6. Stopping the env removes the staged plaintext.
	if err := stop(m.Name); err != nil {
		t.Fatal(err)
	}
	stage, err := secretsStage(m.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); err == nil {
		t.Error("staged plaintext survived stop")
	}
}

// podmanOutAfterUp brings the env up running cmd, capturing its stdout.
func podmanOutAfterUp(t *testing.T, m *Manifest, manifest string, cmd []string) (string, error) {
	t.Helper()
	if err := up(m, manifest, []string{"true"}); err != nil {
		return "", err
	}
	out, err := podmanOut(append([]string{"exec", cname(m.Name)}, cmd...)...)
	return out, err
}

func storePathOf(t *testing.T, m *Manifest) string {
	t.Helper()
	p, err := m.build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func grepTree(t *testing.T, root, needle string) bool {
	t.Helper()
	out, _ := exec.Command("grep", "-rl", needle, root).Output()
	return len(strings.TrimSpace(string(out))) > 0
}
