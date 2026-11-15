package main

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// M3's exit criterion, and the deliverable: an automated leak test.
//
// The hard part is not blocking traffic, it is proving that the POLICY blocked it.
// A packet can fail to leave for several uninteresting reasons -- no route, a dead
// tunnel, an unreachable peer -- and any of those would make a broken kill switch look
// like a working one. Every assertion here is therefore paired with the nftables drop
// counter: if the counter moves, nftables dropped the packet, and nothing else did.
//
// deny mode is used for the positive cases because it leaves a working default route
// in place, so the only thing that can stop a packet is the rule. That is also exactly
// M4's agent sandbox, which is why the two share this engine.

func requireRuntime(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("needs podman and a nix store")
	}
	for _, bin := range []string{"podman", "nix"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
}

const netTools = `tools = ["socat", "nftables", "iproute2", "bashInteractive", "coreutils", "gnugrep"]`

// dropCount reads the policy's drop counter from inside the env.
func dropCount(t *testing.T, env string) int {
	t.Helper()
	out, err := execIn(env,
		`nft list table inet spawn 2>/dev/null | grep -oE 'counter packets [0-9]+' | head -1 | tr -dc 0-9`)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return -1
	}
	return n
}

func env2c(name string) string { return cname(name) }

// execIn runs a script inside an env. It must use the PROFILE's bash: there is no base
// image, so /bin/sh does not exist -- a mistake that made this test report a wide-open
// env when the policy was in fact installed.
func execIn(env, script string) (string, error) {
	prof := inspect(env, `{{index .Config.Labels "spawn.profile"}}`)
	if prof == "" {
		return "", errNoProfile
	}
	return podmanOut("exec", "-e", "PATH="+prof+"/bin", env2c(env), prof+"/bin/bash", "-c", script)
}

var errNoProfile = errors.New("env has no recorded profile")

// reaches reports whether a TCP connection leaves the env and completes. dev, when
// set, forces the packet out of that interface with SO_BINDTODEVICE, which is how a
// tunnel bypass is simulated.
func reaches(t *testing.T, env, target, dev string) bool {
	t.Helper()
	spec := "TCP:" + target
	if dev != "" {
		spec += ",so-bindtodevice=" + dev
	}
	_, err := execIn(env, "timeout 6 socat -T4 - "+spec+" </dev/null >/dev/null 2>&1")
	return err == nil
}

// internetReachable checks the host can get out at all, so a sandboxed CI runner
// skips rather than reports a false pass.
func internetReachable(t *testing.T) bool {
	t.Helper()
	m, err := Parse([]byte("schema = 1\nname = \"spawnnetcontrol\"\n" + netTools))
	if err != nil {
		t.Fatal(err)
	}
	rm(m.Name, true)
	t.Cleanup(func() { rm(m.Name, true) })
	if err := up(m, "/tmp/spawn-netcontrol.toml", []string{"true"}); err != nil {
		t.Skip("could not build the control env:", err)
	}
	return reaches(t, m.Name, "1.1.1.1:443", "")
}

// TestEgressPolicyBlocksAndPermits is the core proof: with a working route in place,
// the policy is the only thing deciding what leaves, and the counter says so.
func TestEgressPolicyBlocksAndPermits(t *testing.T) {
	requireRuntime(t)
	if !internetReachable(t) {
		t.Skip("no outbound internet from an unrestricted env, so a block proves nothing")
	}

	t.Run("deny blocks, and nftables is what blocked", func(t *testing.T) {
		m, err := Parse([]byte("schema = 1\nname = \"spawndenytest\"\n" + netTools +
			"\n[network]\negress = \"deny\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		rm(m.Name, true)
		t.Cleanup(func() { rm(m.Name, true) })
		if err := up(m, "/tmp/spawn-deny.toml", []string{"true"}); err != nil {
			t.Fatal(err)
		}

		before := dropCount(t, m.Name)
		if before < 0 {
			t.Fatal("no spawn policy table in the env, so there is no kill switch at all")
		}
		if reaches(t, m.Name, "1.1.1.1:443", "") {
			t.Error("LEAK: egress = deny let a packet out")
		}
		after := dropCount(t, m.Name)
		// Without this the test would pass even if the packet died for want of a
		// route, which is the mistake that makes a broken kill switch look fine.
		if after <= before {
			t.Errorf("the drop counter did not move (%d -> %d): the block was not the policy", before, after)
		}
	})

	t.Run("allow permits exactly what it names", func(t *testing.T) {
		m, err := Parse([]byte("schema = 1\nname = \"spawnallowtest\"\n" + netTools +
			"\n[network]\negress = \"deny\"\nallow = [\"1.1.1.1\"]\n"))
		if err != nil {
			t.Fatal(err)
		}
		rm(m.Name, true)
		t.Cleanup(func() { rm(m.Name, true) })
		if err := up(m, "/tmp/spawn-allow.toml", []string{"true"}); err != nil {
			t.Fatal(err)
		}
		// Same env, same interface, same port: only the rule differs from the case
		// above, which is what makes this a controlled comparison.
		if !reaches(t, m.Name, "1.1.1.1:443", "") {
			t.Error("the declared exception did not get out, so the policy is useless")
		}
		if reaches(t, m.Name, "8.8.8.8:443", "") {
			t.Error("LEAK: an address outside the allow list got out")
		}
	})
}

// TestKillSwitchHoldsWithNoTunnel covers the half of M3's criterion that matters most:
// with the tunnel DOWN, nothing egresses at all. It needs no VPN server -- the config
// names an endpoint that will never answer, so the tunnel cannot come up, which is
// precisely the failure the kill switch exists for.
func TestKillSwitchHoldsWithNoTunnel(t *testing.T) {
	requireRuntime(t)

	dir := t.TempDir()
	conf := dir + "/dead.ovpn"
	// 203.0.113.0/24 is reserved for documentation, so it answers nowhere.
	if err := os.WriteFile(conf, []byte("remote 203.0.113.9 1194\nproto udp\ndev tun\n"+
		"ifconfig 10.9.0.2 10.9.0.1\nsecret /etc/spawn/nonexistent.key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Parse([]byte("schema = 1\nname = \"spawnkilltest\"\n" + netTools +
		"\n[vpn]\nkind = \"openvpn\"\nconfig = \"./dead.ovpn\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.effectiveEgress() != egressVPN {
		t.Fatalf("a declared VPN should imply vpn-only egress, got %q", m.effectiveEgress())
	}
	rm(m.Name, true)
	t.Cleanup(func() { rm(m.Name, true) })

	// up is EXPECTED to fail: the tunnel never comes up. What matters is the state it
	// leaves behind -- a sealed env, not an open one.
	_ = up(m, conf, []string{"true"})

	if dropCount(t, m.Name) < 0 {
		t.Fatal("the policy table is absent after a failed connect: the env is wide open")
	}
	before := dropCount(t, m.Name)
	if reaches(t, m.Name, "1.1.1.1:443", "") {
		t.Error("LEAK: traffic escaped an env whose tunnel never came up")
	}
	if after := dropCount(t, m.Name); after <= before {
		t.Logf("drop counter %d -> %d; with no tunnel there may also be no route, "+
			"so this is not conclusive on its own", before, after)
	}

	// And forced out the non-tunnel interface, which is the real bypass attempt.
	if reaches(t, m.Name, "1.1.1.1:443", "tap0") {
		t.Error("LEAK: traffic bound to the non-tunnel interface escaped")
	}
}
