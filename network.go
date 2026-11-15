package main

// Egress policy and the VPN kill switch.
//
// The rule that shapes all of this: the policy is installed BEFORE the tunnel is
// started, with a default-drop and a hole only for the VPN endpoint. A kill switch
// applied after the tunnel comes up is not a kill switch -- it leaks for however long
// the handshake takes, and it leaks again if the tunnel dies and something races to
// re-establish it.
//
// nftables matches output interfaces by NAME, so a rule may reference tun0 or wg0
// before that interface exists. That is what makes "deny first, connect second"
// possible at all.
//
// The generator here is a pure function from manifest to nft script, so the policy
// can be tested exhaustively without root, a container, or a VPN.

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type networkConfig struct {
	// allow (default), deny, or vpn.
	Egress string `toml:"egress"`
	// Join a podman network, so several envs can talk to each other directly.
	// Without this an env is behind pasta's NAT and is reachable only through
	// published ports -- which is fine for a shell, but breaks anything that needs
	// a sustained flow between two envs, a VPN datapath being the obvious case.
	Join string `toml:"join"`
	// Exceptions: CIDRs, bare IPs, or proto:port such as "udp:53".
	Allow []string `toml:"allow"`
}

type vpnConfig struct {
	Kind string `toml:"kind"`   // openvpn or wireguard
	Conf string `toml:"config"` // a secret handle ("secret:vpn") or a host path
	// KillSwitch defaults to true: a VPN without one is a false sense of safety.
	KillSwitch *bool `toml:"kill_switch"`
	// RouteAll defaults to true. The kill switch guarantees nothing LEAVES except
	// through the tunnel; this guarantees traffic actually GOES through it. They are
	// different properties: with the switch on and no default route via the tunnel,
	// an env is simply offline, which is safe but rarely what was wanted.
	RouteAll *bool    `toml:"route_all"`
	DNS      []string `toml:"dns"`
}

const (
	egressAllow = "allow"
	egressDeny  = "deny"
	egressVPN   = "vpn"
)

// tunnelIface is the interface name spawn gives the tunnel, so the generated rules
// and the generated connect script agree on it.
func (v vpnConfig) tunnelIface() string {
	if v.Kind == "wireguard" {
		return "wg0"
	}
	return "tun0"
}

func (v vpnConfig) declared() bool { return v.Kind != "" || v.Conf != "" }

func (v vpnConfig) killSwitch() bool {
	return v.KillSwitch == nil || *v.KillSwitch
}

func (v vpnConfig) routeAll() bool {
	return v.RouteAll == nil || *v.RouteAll
}

// effectiveEgress resolves the policy. A declared VPN with its kill switch on implies
// vpn-only egress, so the common case needs no [network] section at all.
func (m *Manifest) effectiveEgress() string {
	if m.Network.Egress != "" {
		return m.Network.Egress
	}
	if m.VPN.declared() && m.VPN.killSwitch() {
		return egressVPN
	}
	return egressAllow
}

var protoPortRe = regexp.MustCompile(`^(tcp|udp):(\d{1,5})$`)

func (m *Manifest) validateNetwork() error {
	switch m.Network.Egress {
	case "", egressAllow, egressDeny, egressVPN:
	default:
		return fmt.Errorf("network.egress %q is not allow, deny or vpn", m.Network.Egress)
	}
	if m.Network.Egress == egressVPN && !m.VPN.declared() {
		return fmt.Errorf("network.egress = \"vpn\" but no [vpn] is declared, " +
			"so nothing would ever be allowed out")
	}
	for _, a := range m.Network.Allow {
		if err := validAllowEntry(a); err != nil {
			return err
		}
	}
	// The name becomes a podman network name and a CLI argument.
	if j := m.Network.Join; j != "" && !attrRe.MatchString(j) {
		return fmt.Errorf("network.join %q is not a plain name", j)
	}
	if v := m.VPN; v.declared() {
		if v.Kind != "openvpn" && v.Kind != "wireguard" {
			return fmt.Errorf("vpn.kind %q is not openvpn or wireguard", v.Kind)
		}
		if v.Conf == "" {
			return fmt.Errorf("vpn.config is required: a secret handle or a path")
		}
		if strings.HasPrefix(v.Conf, "secret:") {
			name := strings.TrimPrefix(v.Conf, "secret:")
			if _, ok := m.Secrets[name]; !ok {
				return fmt.Errorf("vpn.config references secret %q, which is not declared in [secrets]", name)
			}
		}
		for _, d := range v.DNS {
			if net.ParseIP(d) == nil {
				return fmt.Errorf("vpn.dns %q is not an IP address", d)
			}
		}
	}
	return nil
}

func validAllowEntry(a string) error {
	if protoPortRe.MatchString(a) {
		return nil
	}
	if strings.Contains(a, "/") {
		if _, _, err := net.ParseCIDR(a); err == nil {
			return nil
		}
		return fmt.Errorf("network.allow %q is not a valid CIDR", a)
	}
	if net.ParseIP(a) != nil {
		return nil
	}
	return fmt.Errorf("network.allow %q is not an IP, a CIDR, or proto:port like \"udp:53\"", a)
}

// endpoint is a VPN server address, pinned to an IP.
type endpoint struct {
	ip    string
	port  int
	proto string
}

var (
	ovpnRemoteRe = regexp.MustCompile(`(?m)^\s*remote\s+(\S+)(?:\s+(\d+))?(?:\s+(udp|tcp)\S*)?`)
	ovpnProtoRe  = regexp.MustCompile(`(?m)^\s*proto\s+(udp|tcp)`)
	wgEndpointRe = regexp.MustCompile(`(?m)^\s*Endpoint\s*=\s*(\S+)`)
)

// parseEndpoints pulls the server addresses out of a VPN config.
//
// This matters more than it looks: the kill switch has to allow the tunnel itself out,
// and the hole must be as small as possible. Resolving the hostname HERE, on the host,
// before any rule is applied, means the hole is a pinned IP and port -- no DNS has to
// be allowed out of the env, which is exactly the leak a kill switch is meant to stop.
func parseEndpoints(kind, conf string, resolve func(string) ([]net.IP, error)) ([]endpoint, error) {
	if resolve == nil {
		resolve = net.LookupIP
	}
	var hosts []struct {
		host, port, proto string
	}
	if kind == "wireguard" {
		for _, m := range wgEndpointRe.FindAllStringSubmatch(conf, -1) {
			h, p, err := splitHostPort(m[1])
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, struct{ host, port, proto string }{h, p, "udp"})
		}
	} else {
		proto := "udp" // OpenVPN's default
		if pm := ovpnProtoRe.FindStringSubmatch(conf); pm != nil {
			proto = pm[1]
		}
		for _, m := range ovpnRemoteRe.FindAllStringSubmatch(conf, -1) {
			port := m[2]
			if port == "" {
				port = "1194"
			}
			pr := proto
			if m[3] != "" {
				pr = m[3]
			}
			hosts = append(hosts, struct{ host, port, proto string }{m[1], port, pr})
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no server endpoint found in the %s config; "+
			"the kill switch needs it to let the tunnel itself connect", kind)
	}

	var eps []endpoint
	seen := map[string]bool{}
	for _, h := range hosts {
		port, err := strconv.Atoi(h.port)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("endpoint %s has an invalid port %q", h.host, h.port)
		}
		ips := []net.IP{}
		if ip := net.ParseIP(h.host); ip != nil {
			ips = append(ips, ip)
		} else {
			resolved, err := resolve(h.host)
			if err != nil {
				return nil, fmt.Errorf("cannot resolve VPN endpoint %q: %w", h.host, err)
			}
			ips = resolved
		}
		for _, ip := range ips {
			// IPv6 endpoints would need their own rule family; skip rather than
			// emit a rule that silently never matches.
			if ip.To4() == nil {
				continue
			}
			key := fmt.Sprintf("%s/%d/%s", ip, port, h.proto)
			if seen[key] {
				continue
			}
			seen[key] = true
			eps = append(eps, endpoint{ip: ip.String(), port: port, proto: h.proto})
		}
	}
	if len(eps) == 0 {
		return nil, fmt.Errorf("the %s config's endpoints resolved to no IPv4 address", kind)
	}
	return eps, nil
}

func splitHostPort(s string) (string, string, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("endpoint %q is not host:port", s)
	}
	return h, p, nil
}

// nftRuleset renders the egress policy. Empty when the policy is "allow", so an env
// that declares nothing gets no firewall at all.
func (m *Manifest) nftRuleset(eps []endpoint) string {
	mode := m.effectiveEgress()
	if mode == egressAllow {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Generated by spawn. Egress policy: " + mode + "\n")
	b.WriteString("flush ruleset\n\n")
	b.WriteString("table inet spawn {\n")
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority filter; policy drop;\n\n")
	b.WriteString("    # Loopback is never egress.\n")
	b.WriteString("    oifname \"lo\" accept\n")
	b.WriteString("    # Replies to connections the policy already permitted.\n")
	b.WriteString("    ct state established,related accept\n")

	if mode == egressVPN {
		iface := m.VPN.tunnelIface()
		fmt.Fprintf(&b, "\n    # Everything the env sends must leave through the tunnel.\n")
		fmt.Fprintf(&b, "    oifname %q accept\n", iface)
		if len(eps) > 0 {
			b.WriteString("\n    # The tunnel itself, pinned to resolved IPs so no DNS\n")
			b.WriteString("    # has to be allowed out before the tunnel exists.\n")
			for _, e := range eps {
				fmt.Fprintf(&b, "    ip daddr %s %s dport %d accept\n", e.ip, e.proto, e.port)
			}
		}
	}

	if len(m.Network.Allow) > 0 {
		b.WriteString("\n    # network.allow exceptions.\n")
		for _, a := range m.Network.Allow {
			if pm := protoPortRe.FindStringSubmatch(a); pm != nil {
				fmt.Fprintf(&b, "    %s dport %s accept\n", pm[1], pm[2])
				continue
			}
			fmt.Fprintf(&b, "    ip daddr %s accept\n", a)
		}
	}

	// Counting what is dropped turns "it seems fine" into something auditable, and
	// M4's agent audit log needs exactly this.
	b.WriteString("\n    counter comment \"spawn-dropped\"\n")
	b.WriteString("  }\n}\n")
	return b.String()
}
