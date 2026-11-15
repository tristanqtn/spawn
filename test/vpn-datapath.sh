#!/usr/bin/env bash
# M3 datapath proof: a real encrypted payload crossing a real tunnel, for both
# OpenVPN and WireGuard, with the kill switch in force throughout.
#
# Why this is a script and not a Go test: it needs a second env acting as the VPN
# server, with keys generated inside it. The Go tests cover the policy engine and the
# leak assertions; this covers "a payload actually crosses the tunnel".
#
# The envs join a shared podman network (network.join). That matters: reaching the
# server through a host-PUBLISHED UDP port forwards the handshake and then silently
# stops forwarding -- the server's receive counter freezes while the client
# retransmits. Both OpenVPN and WireGuard behave that way, so it is the rootless
# published-port path, not the tunnel.
#
# Usage: test/vpn-datapath.sh     (needs spawn on PATH, podman, and a nix store)
set -u
R=${SPAWN_TEST_DIR:-$HOME/.cache/spawn-datapath-test}
rm -rf "$R"; mkdir -p "$R"; cd "$R"
fail=0
ok()   { printf '  [PASS] %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=1; }

cat > server.toml <<'EOF'
schema = 1
name = "dpsrv"
tools = ["openvpn", "wireguard-tools", "wireguard-go", "iproute2", "socat", "bashInteractive", "coreutils", "gnugrep"]
caps = ["NET_ADMIN", "NET_RAW"]
devices = ["/dev/net/tun"]

[network]
join = "spawnlab"
EOF
spawn rm dpsrv >/dev/null 2>&1
spawn up server.toml true >/dev/null 2>&1 || { echo "could not build the server env"; exit 1; }
SRVIP=$(podman inspect spawn-dpsrv -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
[ -n "$SRVIP" ] || { echo "the env got no address on the shared network"; exit 1; }
echo "server on the shared network: $SRVIP"

E=$HOME/.local/share/spawn/envs/dpsrv/rootfs/etc
P=$(podman inspect spawn-dpsrv -f '{{index .Config.Labels "spawn.profile"}}')

# --- OpenVPN ---------------------------------------------------------------------
spawn up dpsrv bash -c '
  echo DATAPATH-OK > /etc/probe.txt
  test -f /etc/dp.key || openvpn --genkey secret /etc/dp.key
  ip link show tun0 >/dev/null 2>&1 || openvpn --dev tun0 --ifconfig 10.9.0.1 10.9.0.2 \
    --secret /etc/dp.key --proto udp --port 1194 --cipher AES-256-CBC --auth SHA256 \
    --daemon --log /tmp/ovpn.log
  sleep 1' >/dev/null 2>&1
podman exec -d spawn-dpsrv "$P/bin/socat" TCP-LISTEN:5555,fork,reuseaddr OPEN:/etc/probe.txt 2>/dev/null

{ printf 'remote %s 1194\nproto udp\ndev tun\nifconfig 10.9.0.2 10.9.0.1\n' "$SRVIP"
  printf 'cipher AES-256-CBC\nauth SHA256\n<secret>\n'; cat "$E/dp.key"; printf '</secret>\n'
} > client.ovpn
cat > client.toml <<EOF
schema = 1
name = "dpcli"
tools = ["socat", "nftables", "iproute2", "bashInteractive", "coreutils", "gnugrep"]
[network]
join = "spawnlab"
[vpn]
kind = "openvpn"
config = "./client.ovpn"
EOF
spawn rm dpcli >/dev/null 2>&1
spawn up client.toml true >/dev/null 2>&1
got=$(spawn up dpcli bash -c 'timeout 6 socat -T4 - TCP:10.9.0.1:5555 2>/dev/null | head -1' 2>/dev/null | tr -d '\r')
[ "$got" = DATAPATH-OK ] && ok "OpenVPN: payload crossed the tunnel" || bad "OpenVPN: got '$got'"

# The switch must still seal everything that is not the tunnel.
got=$(spawn up dpcli bash -c 'timeout 5 socat -T3 - TCP:1.1.1.1:443,so-bindtodevice=eth0 </dev/null >/dev/null 2>&1 && echo REACHED || echo blocked' 2>/dev/null | tr -d '\r')
[ "$got" = blocked ] && ok "OpenVPN: kill switch sealed the non-tunnel interface" || bad "LEAK: $got"

# --- WireGuard -------------------------------------------------------------------
spawn up dpsrv bash -c '
  cd /etc
  test -f wgs.key || { wg genkey > wgs.key; wg pubkey < wgs.key > wgs.pub; }
  test -f wgc.key || { wg genkey > wgc.key; wg pubkey < wgc.key > wgc.pub; }
  ip link show wgs >/dev/null 2>&1 || ip link add wgs type wireguard
  printf "[Interface]\nPrivateKey = %s\nListenPort = 51820\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.55.0.2/32\n" \
    "$(cat wgs.key)" "$(cat wgc.pub)" > wgs.conf
  wg setconf wgs /etc/wgs.conf
  ip addr replace 10.55.0.1/24 dev wgs
  ip link set wgs up' >/dev/null 2>&1
podman exec -d spawn-dpsrv "$P/bin/socat" TCP-LISTEN:5556,fork,reuseaddr OPEN:/etc/probe.txt 2>/dev/null

printf '[Interface]\nPrivateKey = %s\nAddress = 10.55.0.2/24\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 10.55.0.0/24\nPersistentKeepalive = 10\n' \
  "$(cat "$E/wgc.key")" "$(cat "$E/wgs.pub")" "$SRVIP" > wgcli.conf
cat > wgcli.toml <<EOF
schema = 1
name = "dpwg"
tools = ["socat", "nftables", "iproute2", "bashInteractive", "coreutils", "gnugrep"]
[network]
join = "spawnlab"
[vpn]
kind = "wireguard"
config = "./wgcli.conf"
route_all = false
EOF
spawn rm dpwg >/dev/null 2>&1
spawn up wgcli.toml true >/dev/null 2>&1
sleep 3
hs=$(spawn up dpwg bash -c 'wg show wg0 latest-handshakes' 2>/dev/null | tr -d '\r')
case "$hs" in *"	0"|"") bad "WireGuard: no handshake ($hs)" ;; *) ok "WireGuard: handshake completed" ;; esac
got=$(spawn up dpwg bash -c 'timeout 6 socat -T4 - TCP:10.55.0.1:5556 2>/dev/null | head -1' 2>/dev/null | tr -d '\r')
[ "$got" = DATAPATH-OK ] && ok "WireGuard: payload crossed the tunnel" || bad "WireGuard: got '$got'"

for e in dpcli dpwg dpsrv; do spawn rm "$e" --purge >/dev/null 2>&1; done
exit $fail
