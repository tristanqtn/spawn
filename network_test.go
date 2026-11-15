package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
)

func TestNetworkValidationRejects(t *testing.T) {
	bad := map[string]string{
		"unknown egress mode": `[network]` + "\n" + `egress = "maybe"`,
		// vpn-only egress with no VPN would drop everything forever.
		"vpn egress with no vpn": `[network]` + "\n" + `egress = "vpn"`,
		"allow not an address":   `[network]` + "\n" + `allow = ["example.com"]`,
		"allow bad cidr":         `[network]` + "\n" + `allow = ["10.0.0.0/99"]`,
		"allow bad proto":        `[network]` + "\n" + `allow = ["sctp:1"]`,
		"unknown vpn kind":       `[vpn]` + "\n" + `kind = "ipsec"` + "\n" + `config = "./x.conf"`,
		"vpn with no config":     `[vpn]` + "\n" + `kind = "openvpn"`,
		"vpn dns not an ip":      `[vpn]` + "\n" + `kind = "openvpn"` + "\n" + `config = "./x"` + "\n" + `dns = ["ns.lab"]`,
		// A secret handle that names nothing is a typo that would otherwise surface
		// as a missing file much later.
		"vpn secret not declared": `[vpn]` + "\n" + `kind = "openvpn"` + "\n" + `config = "secret:nope"`,
	}
	for why, field := range bad {
		src := "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n" + field + "\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}

	ok := "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n" +
		"[network]\negress = \"deny\"\nallow = [\"10.10.0.0/16\", \"1.1.1.1\", \"udp:53\", \"tcp:443\"]\n"
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("rejected a valid policy: %v", err)
	}
}

// A declared VPN implies vpn-only egress, so the common case needs no [network].
func TestEffectiveEgress(t *testing.T) {
	plain := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]")
	if plain.effectiveEgress() != egressAllow {
		t.Error("an env with no policy should not get a firewall")
	}
	if plain.nftRuleset(nil) != "" {
		t.Error("allow-mode must generate no ruleset at all")
	}

	vpn := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[vpn]\nkind = \"openvpn\"\nconfig = \"./lab.ovpn\"\n")
	if vpn.effectiveEgress() != egressVPN {
		t.Error("a declared VPN should imply vpn-only egress")
	}

	// Opting out is explicit, and then there is no firewall.
	off := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[vpn]\nkind = \"openvpn\"\nconfig = \"./lab.ovpn\"\nkill_switch = false\n")
	if off.effectiveEgress() != egressAllow {
		t.Errorf("kill_switch = false should leave egress open, got %q", off.effectiveEgress())
	}
}

// The VPN and the firewall need privileges; spawn adds them rather than letting the
// user discover that nftables silently did nothing.
func TestNetworkAddsItsPackagesAndPrivileges(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[vpn]\nkind = \"wireguard\"\nconfig = \"./wg.conf\"\n")
	for _, want := range []string{"nftables", "iproute2", "wireguard-tools", "wireguard-go"} {
		if !m.has(want) {
			t.Errorf("a wireguard VPN did not pull in %s", want)
		}
	}
	if !contains(m.Caps, "NET_ADMIN") || !contains(m.Caps, "NET_RAW") {
		t.Errorf("caps = %v, want NET_ADMIN and NET_RAW", m.Caps)
	}
	if !contains(m.Devices, "/dev/net/tun") {
		t.Errorf("devices = %v, want /dev/net/tun", m.Devices)
	}
	// Declaring them as well must not duplicate them.
	dup := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"caps = [\"NET_ADMIN\"]\ndevices = [\"/dev/net/tun\"]\n"+
		"[vpn]\nkind = \"openvpn\"\nconfig = \"./x.ovpn\"\n")
	if n := count(dup.Caps, "NET_ADMIN"); n != 1 {
		t.Errorf("NET_ADMIN appears %d times", n)
	}
	if n := count(dup.Devices, "/dev/net/tun"); n != 1 {
		t.Errorf("/dev/net/tun appears %d times", n)
	}
}

// The ruleset is the kill switch. Every claim it makes is checked here, because the
// integration test can only prove one configuration at a time.
func TestNftRulesetVPNMode(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[vpn]\nkind = \"openvpn\"\nconfig = \"./lab.ovpn\"\n"+
		"[network]\nallow = [\"10.10.0.0/16\", \"udp:53\"]\n")
	rs := m.nftRuleset([]endpoint{{ip: "203.0.113.7", port: 1194, proto: "udp"}})

	for _, want := range []string{
		"policy drop;",                            // default deny, not default allow
		`oifname "lo" accept`,                     // loopback is not egress
		`oifname "tun0" accept`,                   // the tunnel
		"ip daddr 203.0.113.7 udp dport 1194 acc", // the pinned endpoint hole
		"ip daddr 10.10.0.0/16 accept",            // an explicit exception
		"udp dport 53 accept",
		"ct state established,related accept",
		"spawn-dropped", // auditable, which M4 needs
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
	// It must not permit anything by hostname: name resolution is the classic leak.
	if strings.Contains(rs, "example") || strings.Contains(rs, "lab.ovpn") {
		t.Errorf("ruleset references a name rather than an address:\n%s", rs)
	}
}

// deny mode is M4's agent sandbox: no tunnel, nothing out but explicit exceptions.
func TestNftRulesetDenyMode(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[network]\negress = \"deny\"\nallow = [\"1.1.1.1\"]\n")
	rs := m.nftRuleset(nil)
	if !strings.Contains(rs, "policy drop;") {
		t.Error("deny mode must default-drop")
	}
	if strings.Contains(rs, "tun0") || strings.Contains(rs, "wg0") {
		t.Errorf("deny mode must not reference a tunnel:\n%s", rs)
	}
	if !strings.Contains(rs, "ip daddr 1.1.1.1 accept") {
		t.Error("deny mode dropped its allow list")
	}
}

func TestWireguardUsesItsOwnInterface(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[vpn]\nkind = \"wireguard\"\nconfig = \"./wg.conf\"\n")
	rs := m.nftRuleset(nil)
	if !strings.Contains(rs, `oifname "wg0" accept`) {
		t.Errorf("wireguard ruleset should name wg0:\n%s", rs)
	}
	if strings.Contains(rs, "tun0") {
		t.Error("wireguard ruleset should not name tun0")
	}
}

// Endpoint parsing is what keeps the hole in the firewall small. If it silently found
// nothing, the tunnel could never connect; if it found too much, the hole is wide.
func TestParseEndpointsOpenVPN(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		if host == "vpn.lab.example" {
			return []net.IP{net.ParseIP("198.51.100.4")}, nil
		}
		return nil, fmt.Errorf("unexpected lookup of %q", host)
	}

	eps, err := parseEndpoints("openvpn", "client\ndev tun\nproto tcp\nremote vpn.lab.example 443 tcp\n", resolve)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].ip != "198.51.100.4" || eps[0].port != 443 || eps[0].proto != "tcp" {
		t.Errorf("got %+v", eps)
	}

	// The default port and protocol, when the config omits them.
	eps, err = parseEndpoints("openvpn", "remote 203.0.113.9\n", resolve)
	if err != nil {
		t.Fatal(err)
	}
	if eps[0].port != 1194 || eps[0].proto != "udp" {
		t.Errorf("OpenVPN defaults wrong: %+v", eps[0])
	}

	// Multiple remotes are a failover list, so all of them need a hole.
	eps, err = parseEndpoints("openvpn", "remote 203.0.113.1 1194\nremote 203.0.113.2 1195\n", resolve)
	if err != nil || len(eps) != 2 {
		t.Errorf("failover remotes: %+v (%v)", eps, err)
	}

	// A config with no remote cannot be made safe, so it must be an error rather
	// than a ruleset that blocks the tunnel it is meant to permit.
	if _, err := parseEndpoints("openvpn", "client\ndev tun\n", resolve); err == nil {
		t.Error("a config with no remote should be rejected")
	}
}

func TestParseEndpointsWireGuard(t *testing.T) {
	conf := "[Interface]\nPrivateKey = x\nAddress = 10.44.0.2/24\n\n" +
		"[Peer]\nPublicKey = y\nEndpoint = 192.0.2.50:51820\nAllowedIPs = 0.0.0.0/0\n"
	eps, err := parseEndpoints("wireguard", conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].ip != "192.0.2.50" || eps[0].port != 51820 || eps[0].proto != "udp" {
		t.Errorf("got %+v", eps)
	}
	if _, err := parseEndpoints("wireguard", "[Interface]\nPrivateKey = x\n", nil); err == nil {
		t.Error("a peerless config should be rejected")
	}
	if _, err := parseEndpoints("wireguard", "[Peer]\nEndpoint = 192.0.2.50\n", nil); err == nil {
		t.Error("an endpoint without a port should be rejected")
	}
}

// An IPv6-only endpoint would produce an ip (v4) rule that never matches, so it must
// be reported rather than silently generating a firewall the tunnel cannot cross.
func TestParseEndpointsRejectsIPv6Only(t *testing.T) {
	resolve := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::1")}, nil
	}
	if _, err := parseEndpoints("openvpn", "remote vpn6.example 1194\n", resolve); err == nil {
		t.Error("an IPv6-only endpoint should be an error, not a silent no-op")
	}
}

// The script's ordering is the safety property: policy before connect.
func TestNetupScriptAppliesPolicyBeforeConnecting(t *testing.T) {
	m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
		"[vpn]\nkind = \"openvpn\"\nconfig = \"./lab.ovpn\"\n")
	s := m.netupScript("/nix/store/p")
	nft, ovpn := strings.Index(s, "nft -f"), strings.Index(s, "openvpn --config")
	if nft < 0 || ovpn < 0 {
		t.Fatalf("script is missing a step:\n%s", s)
	}
	if nft > ovpn {
		t.Error("the policy must be applied BEFORE the tunnel starts, or it leaks during the handshake")
	}
	// A failure to apply the policy must abort rather than connect unprotected.
	if !strings.Contains(s, "FAILED to apply the egress policy") {
		t.Error("the script does not abort when the policy cannot be applied")
	}
	// And a tunnel that never arrives must not look like success.
	if !strings.Contains(s, "did not come up") || !strings.Contains(s, "exit 1") {
		t.Error("the script does not fail when the tunnel never comes up")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func count(ss []string, want string) int {
	n := 0
	for _, s := range ss {
		if s == want {
			n++
		}
	}
	return n
}

// The generated script may only use what spawn installs. An earlier version reached
// for sed, grep and pgrep -- none of which spawn adds -- and a WireGuard tunnel came
// up with no address at all, silently, because the line parsing the config could not
// run. This is the regression guard.
func TestNetupScriptUsesNoUninstalledTools(t *testing.T) {
	for _, kind := range []string{"openvpn", "wireguard"} {
		m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
			"[vpn]\nkind = \""+kind+"\"\nconfig = \"./c.conf\"\n")
		s := m.netupScript("/nix/store/p")
		// Anything spawn does not install for a VPN env.
		for _, forbidden := range []string{"sed ", "grep ", "pgrep", "awk ", "cut ", "tr "} {
			if strings.Contains(s, forbidden) {
				t.Errorf("%s script calls %q, which spawn does not install:\n%s", kind, forbidden, s)
			}
		}
		// And it must still actually parse the config it needs to.
		if kind == "wireguard" && !strings.Contains(s, "ini_values") {
			t.Error("the wireguard script lost its config parsing")
		}
	}
}

// The bash emitted for WireGuard has to be syntactically valid, which a Go test can
// check cheaply by asking bash itself.
func TestNetupScriptIsValidBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash on PATH")
	}
	for _, kind := range []string{"openvpn", "wireguard"} {
		m := mustParse(t, "schema = 1\nname = \"x\"\ntools = [\"nmap\"]\n"+
			"[vpn]\nkind = \""+kind+"\"\nconfig = \"./c.conf\"\n")
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(m.netupScript("/nix/store/p"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s script is not valid bash: %v\n%s", kind, err, out)
		}
	}
}
