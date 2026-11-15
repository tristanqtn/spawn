# spawn

Declarative, disposable environments. One file describes a box; spawn builds it
reproducibly and runs it anywhere — for you or for your agent.

```toml
# spawn.toml
schema = 1
name = "lab"
profiles = ["general", "active-directory"]
tools = ["masscan"]

env     = { LAB = "htb" }
mounts  = ["./loot:/loot", "~/.ssh:/root/.ssh:ro"]   # relative to THIS file
ports   = ["127.0.0.1:18080:8080"]
persist = ["/loot", "/root/.msf4"]                   # outlives `spawn rm`
caps    = ["NET_ADMIN", "NET_RAW"]
devices = ["/dev/net/tun"]

[limits]
cpus = "2"
memory = "4g"
pids = 512

[hooks]
post_start = ["echo ready > /root/.ready"]

[secrets]
vpn   = "age:~/secrets/htb.ovpn.age"
token = "sops:./secrets.yaml"
```

Change any of it and the next `spawn up` recreates the container to match, keeping the
rootfs. Relative mount paths resolve against the manifest's own directory, not your
working directory, so a manifest means the same thing wherever you run it from.

`caps` and `devices` are first-class and visible on purpose. Omit `NET_RAW` and `ping`
fails *at exec* with `Operation not permitted` while `nmap -sT` dies with
`dnet: Failed to open device eth0` — neither error names the cause. The privilege an env
holds is exactly what you want to be able to read off the file.

Measured on WSL2: `cpus`, `memory` and `pids` all take effect (`memory.max`, `pids.max`
and `cpu.max` are set inside the env). `io` is not delegated there, so there is no
`limits.io`.

```
spawn init          # write a configured manifest + editable dotfiles here
spawn up            # build ./spawn.toml and enter it
spawn up lab.toml   # ...or a manifest by path
spawn up lab        # ...or an env you already have, from any directory
spawn check         # evaluate the manifest, download nothing
spawn ls            # list envs
spawn stop <name>   # stop an env, keeping its rootfs
spawn rm <name>     # destroy an env and its rootfs
spawn doctor        # check this host, and a manifest against it
spawn profiles      # list the built-in suites
spawn completion    # print a shell completion script
```

Tables are for people. `spawn profiles --names` prints one suite name per line with no
header or rule, and that is the form to parse in a script — the table's layout is not a
contract.

Run `spawn` with no arguments for the help screen.

## Shell completion

```
spawn completion bash > /etc/bash_completion.d/spawn
spawn completion zsh  > "${fpath[1]}/_spawn"
spawn completion fish > ~/.config/fish/completions/spawn.fish
```

Completion is **dynamic**: `spawn stop <tab>` offers only running envs, `spawn rm <tab>`
offers every env plus `--purge`, and `spawn up <tab>` offers the manifests in the
current directory. Each script is a few lines that delegate to a hidden
`spawn __complete`, so the candidate logic lives in Go once instead of being rewritten
in three shell dialects — which is also why spawn needs no CLI framework.

`spawn doctor` exists because the failures here name nothing useful. Without `NET_RAW`,
`ping` fails *at exec* with `Operation not permitted` and `nmap` dies with
`dnet: Failed to open device eth0`. A cgroup limit the kernel silently ignores looks
like it worked. Rootless podman refuses to run under `sg`/`newgrp` with an error that
only mentions `newuidmap`. Every check ends in the manifest field or host action that
fixes it, rather than just saying something is broken.

`spawn up <name>` is how you get back into a running box without hunting for its
manifest: the container records where that manifest is, so spawn re-reads it, rebuilds
if it changed, and drops you in. Tab-completion offers env names and local manifests
together. If the manifest has moved or been deleted the env is still perfectly usable,
so spawn attaches using the profile recorded on the container rather than refusing —
that path needs no nix build at all, which also makes it the quick way in.

An env name only wins when an env by that name exists, so `spawn up ls` runs `ls` in the
default env unless you happen to have an env called `ls`.

An env outlives the shell you entered it from, so `spawn up` twice puts you back in the
same box. The manifest stays the source of truth: change it and the container is
recreated, but the env's writable rootfs is kept, so you get the new tools without
losing what you wrote. spawn keeps no state file — the name, resolved profile and
manifest path are podman labels, and `podman ps` is the source of truth.

## Built-in suites

| Suite | For |
|---|---|
| `general` | the shell you actually want — git, ripgrep, jq, python3, net tools |
| `active-directory` | netexec, impacket, BloodHound CE + neo4j, responder, certipy, kerbrute |
| `web` | ffuf, sqlmap, nuclei, nikto, dalfox, httpx, katana, zap |
| `ctf` | pwntools, gdb, radare2, ghidra, stego and crypto helpers |
| `forensics` | sleuthkit, autopsy, bulk_extractor, yara, libewf |

Suites compose: listing several merges and deduplicates their tools, and `tools`
adds anything else from nixpkgs on top.

Burp Suite, wpscan and volatility3 are **absent on purpose** — all three are unfree in
nixpkgs, and one unfree attribute breaks the whole suite's evaluation. Opt in per
manifest and add them yourself:

```toml
allow_unfree = true
allow_insecure = ["bloodhound-4.3.1"]   # by versioned name, not a blanket switch
tools = ["burpsuite", "wpscan", "volatility3"]
```

These are manifest fields rather than an environment variable spawn sets for you,
because allowing unfree or known-vulnerable code is your decision and should be visible
when someone reads the file.

## Starting from a template

```
spawn init
```

writes a working manifest and a set of **real dotfiles** next to it:

```
spawn.toml                   wired to everything below
dotfiles/starship.toml       the Exegol prompt, in Dracula
dotfiles/tmux.conf           Dracula status bar, sane bindings
dotfiles/bat.conf            Dracula theme
dotfiles/gitconfig           difftastic as the diff tool
dotfiles/nvim/init.lua       no plugin manager, so it starts instantly
workspace/                   mounted at /workspace
```

This is the Exegol *my-resources* idea, except the resources are files in **your**
repository rather than a directory inside an image. Edit them, diff them, commit them.
Re-run `spawn up` and the change lands in a **running** env, so you can iterate on the
prompt or the tmux bar without rebuilding anything.

`spawn init` never overwrites a file you have edited; `--force` restores the shipped
version.

### The prompt

The template reproduces Exegol's prompt in Dracula:

```
[Nov 15, 2026 - 19:05:43 (CET)] lab /workspace #
```

`SPAWN_ENV` is set in every env, so the prompt names the box you are in. The clock is
local time: spawn copies the host's zone file to `/etc/localtime`, because without it an
env is UTC and the clock is quietly wrong. (Pointing `TZDIR` at the profile does *not*
work — nixpkgs `tzdata` does not put `zoneinfo` in the installed output, so `date`
printed UTC with `Europe` as the zone abbreviation.)

If you would rather not keep a starship file at all, `prompt = "exegol"` builds the same
thing in, with nothing to edit:

```toml
[shell]
use = "zsh"
prompt = "exegol"
```

`workdir` sets where a shell starts, `/root` by default and `/workspace` in the template.

## A shell you'd choose to live in

The `general` suite ships fzf, zoxide, eza, bat, starship, tmux, neovim, btop, direnv
and the rest. `[shell]` wires them together so you do not paste the same six
`eval "$(... init zsh)"` lines into every manifest:

```toml
[shell]
use = "zsh"              # bash (default) or zsh
prompt = "starship"      # plain (default), starship, or exegol
history = true           # default when [shell] is present; see below
aliases = { ll = "eza -l --git", lt = "eza --tree --level=2", v = "nvim", cat = "bat -p" }
init = '''
export EDITOR=nvim
bindkey -e
'''
```

That generates `~/.zshrc` with starship, zoxide, direnv, fzf key bindings and
completion, zsh autosuggestions and syntax highlighting in the right order, history
settings, your aliases, then `init` last so it can override anything above it.

**Integrations are not a list you maintain.** spawn already knows every package in the
env, so each one is wired up when its tool is present and left out entirely when it is
not — change `tools` and the rc follows.

`[shell]` also pulls in what it implies: `use = "zsh"` adds zsh, `prompt = "starship"`
adds starship. And because history has to live somewhere that survives, `history = true`
adds `/root/.local/state` to `persist` and points `HISTFILE` at it. `spawn check` shows
both, so neither is a surprise.

Want your own config instead? Declare the rc path in `files` and it replaces the
generated one wholesale — `[shell]` is a convenience, not a gate.

## Configuring the tools, not just installing them

For a config you already own, `files` declares it:

```toml
[files]
# From a real dotfile on the host: edit it with syntax highlighting, keep it in git.
"/root/.tmux.conf"    = { from = "./dotfiles/tmux.conf" }
# A whole directory, so a plugin manager can write its lockfile next to init.lua.
"/root/.config/nvim"  = { from = "./dotfiles/nvim" }
# Tighten the mode where it matters.
"/root/.ssh/config"   = { from = "./dotfiles/ssh_config", mode = "0600" }

# Or inline. TOML literal strings need no escaping, which suits shell config.
[files."/root/.zshrc"]
content = '''
eval "$(starship init zsh)"
source "$(fzf-share)/key-bindings.zsh"
alias ls=eza
'''
```

**`files` copies; it does not mount.** That distinction is the whole point. A
bind-mounted dotfile is read-only, so every tool that rewrites its own config breaks —
neovim writing `lazy-lock.json`, `gh` writing `hosts.yml`, `bat` building a cache. A
copied file is a real, writable file.

Order of precedence, loosest to tightest: spawn's `/etc` identity files, then the
`[shell]`-generated rc, then `files`. Yours always wins.

It works because `--rootfs` is a plain host directory, so seeding a file into an env is
ordinary file copying — no podman involved, and it applies to a **running** env.
Edit a dotfile, re-run `spawn up`, and the change is in the box.

Declared files are **authoritative and overwritten on every `up`**. That is the point of
declaring them: the manifest wins. If you tweak one inside the env and want to keep the
tweak, copy it back to the host file. For state you want to survive regardless — shell
history, caches — use `persist` and point the tool at it (`HISTFILE=/root/.local/state/...`).

Declaring a file underneath a `persist` entry or a `mounts` target is an error, because
the mount would silently hide it.

### What spawn provides on its own

There is no base image, so there is no `/etc/passwd` either — and without it every
`getpwuid()` call fails: `zsh` reports `can't drop privileges`, `ssh` refuses to start,
`tmux` cannot find a login shell. spawn therefore seeds `/etc/passwd`, `/etc/group`,
`/etc/nsswitch.conf` and `/etc/shells` on every `up`, with the profile's bash as the
login shell since `/bin/bash` does not exist. Declare any of those in `files` to
override it.

## For an agent: `spawn mcp`

```
spawn mcp        # MCP server over stdio
```

Eight tools: `spawn_create`, `spawn_exec`, `spawn_diff`, `spawn_audit`,
`spawn_snapshot`, `spawn_restore`, `spawn_list`, `spawn_destroy`.

It is a subcommand rather than a separate binary because it needs every bit of the
manifest, policy and lifecycle code that is already here; a second module would be a
second release to keep in step for no one's benefit.

**Agent envs are deny-by-default on egress.** An agent that needs the network names the
addresses, and everything refused lands in the audit log it can read back. The tool
descriptions are part of the design: they are the only thing telling an agent *when*
reaching for a sandbox is the right move.

`test/agent-loop.py` drives the whole thing with no human in the loop — provision, run a
task, inspect what changed, see what was refused, snapshot, break it, restore, destroy —
and asserts each step. Two bugs it found, both invisible from the CLI:

- Everything in spawn reports progress with `fmt.Printf`, which writes to stdout — and
  on this transport **stdout carries the protocol**, so one "removed env …" line made the
  agent see malformed JSON. In MCP mode `os.Stdout` now points at stderr and the real
  handle is kept for protocol only.
- `spawn_restore` removes the container before swapping the filesystem, so the next
  `spawn_exec` reported "no environment named …" and the agent had no way to recover. The
  server now records the manifest it created the env from and brings it back.

## Snapshots, forks and diffs

```
spawn diff <env>              every file the env changed
spawn snapshot <env> [tag]    copy its filesystem aside
spawn snapshots <env>         list them
spawn restore <env> <tag>     put one back
spawn fork <env> <new-name>   copy it into a new env
```

W0 planned to use `podman commit` for this. That turns out to be impossible:

```
Error: cannot commit a container that uses an exploded rootfs
```

a direct consequence of having no base image. The replacement is better than the plan.
Because `/nix` is mounted rather than copied, an env's rootfs contains **only what the
env itself wrote** — a couple of hundred kilobytes, not a gigabyte. So a snapshot is a
directory copy, a fork is a directory copy, and a diff can afford to hash every file.

`diff` compares against a baseline recorded once, right after spawn finishes seeding, so
it reports what the *env* changed and never what spawn put there. The baseline stores a
hash rather than size and mtime, so a same-length edit is still caught. A fork carries
the baseline with it, so `spawn diff` on the fork still measures from the original
starting point. Forking is commit-then-start, never live migration: CRIU is unavailable
on the WSL2 kernel, so running processes are not copied.

Measured: two envs from one tool set share a **232 MB** closure, and the second env's own
files come to **3,264 bytes — 0.0014%** of it. That is the whole economic case for agent
sandboxes, so there is a test asserting it rather than a claim in a README. Note the
limit of it: W0 measured that reuse *across different* profiles is only ~10%, so this
holds for many instances of one profile, which is exactly the agent case.

## VPN and the kill switch

```toml
[vpn]
kind = "openvpn"              # or "wireguard"
config = "secret:vpn"         # a secret handle, or ./lab.ovpn
# kill_switch = true          # default
# route_all  = true           # default

[network]
egress = "vpn"                # implied by [vpn]; also "deny" or "allow"
allow  = ["10.10.0.0/16", "udp:53"]
```

Declaring `[vpn]` is enough: spawn adds openvpn or wireguard-tools, nftables and
iproute2, plus `NET_ADMIN`, `NET_RAW` and `/dev/net/tun`, and turns the kill switch on.
`spawn check` prints the effective privileges, so nothing is hidden.

**The ordering is the safety property.** The default-drop ruleset is installed *before*
the VPN client starts, because a kill switch applied afterwards leaks for the length of
the handshake and leaks again every time the tunnel drops. That is possible because
nftables matches the output interface by *name*, so a rule can reference `tun0` before
it exists.

**The hole for the tunnel is a pinned IP.** spawn resolves the endpoint from the config
on the host, before any rule is applied, and allows exactly that address and port. No
DNS has to be permitted out of the env — DNS escaping the tunnel is the classic leak a
kill switch is supposed to prevent. With `egress = "vpn"` the host resolver is
unreachable by design; use `vpn.dns` for a resolver that lives inside the tunnel.

`kill_switch` and `route_all` are separate guarantees: the switch stops traffic leaving
by any other route, `route_all` makes traffic actually *use* the tunnel. With the switch
on and no default route through the tunnel an env is simply offline — safe, but rarely
what was wanted.

### The leak test

`TestEgressPolicyBlocksAndPermits` and `TestKillSwitchHoldsWithNoTunnel` are the
milestone's deliverable, not a nicety. The difficult part is not blocking traffic but
proving the *policy* blocked it: a packet can also fail for want of a route, a dead
tunnel or an unreachable peer, and any of those makes a broken kill switch look like a
working one. So every assertion is paired with the nftables drop counter:

```
deny mode, internet            blocked, counter 1 -> 6   (nftables dropped it)
deny + allow = ["1.1.1.1"]     1.1.1.1 REACHED, 8.8.8.8 blocked
kill switch, forced out tap0   blocked, counter 0 -> 5
tunnel-bound traffic           counter unchanged, so accepted
tunnel never came up           sealed, nothing egresses
```

The positive cases use `egress = "deny"`, which leaves a working default route in place
so the rule is the only thing that can stop a packet. That mode is also M4's agent
sandbox, which is why they share one engine.

### The egress audit log

```
$ spawn audit agent
REFUSED DESTINATION  FORGOTTEN IN
-------------------  ------------
8.8.8.8              23h59m55s
9.9.9.9              23h59m58s

2 destination(s) refused by the egress policy
```

The policy keeps a dynamic nftables set of every destination it refused, so the question
"what did the agent try to reach" has an answer. A counter cannot answer it, and
`nft log` writes to the kernel log, which a rootless env cannot read — the set is
readable from inside the env itself. Entries expire after 24h, so nothing has to prune
it. Allowed destinations never appear: an audit that lists permitted traffic as refused
trains you to ignore it.

### The datapath proof

`test/vpn-datapath.sh` builds a real VPN server as a second env and pushes a payload
across both kinds of tunnel, with the kill switch in force:

```
[PASS] OpenVPN: payload crossed the tunnel
[PASS] OpenVPN: kill switch sealed the non-tunnel interface
[PASS] WireGuard: handshake completed
[PASS] WireGuard: payload crossed the tunnel
```

WireGuard uses the kernel module, which autoloads on the netlink request even in a
rootless userns, and falls back to `wireguard-go` in userspace when it is unavailable —
so WireGuard works anywhere OpenVPN does.

That script exists in this form because of a trap worth knowing about. Reaching the
server through a **host-published UDP port** forwards the handshake and then silently
stops: the server's receive counter freezes while the client retransmits. Both OpenVPN
and WireGuard do it, so it is the rootless published-port path, not the tunnel. The fix
is `network.join`, which puts both envs on a shared podman network so they talk
directly:

```toml
[network]
join = "spawnlab"
```

Without it each env sits behind its own NAT and is reachable only through published
ports, which is fine for a shell and wrong for anything needing a sustained flow.

## Secrets

A secret is referenced by path to an **encrypted** file. spawn decrypts it into a tmpfs
directory (mode 0700, files 0600) and bind-mounts that read-only at `/run/secrets/<name>`:

```
age:<path>    age-encrypted, decrypted with SPAWN_AGE_IDENTITY or
              ~/.config/sops/age/keys.txt
sops:<path>   anything sops can decrypt
file:<path>   an unencrypted file, named honestly for what it is
```

`age` and `sops` come from the **same pinned nixpkgs** as your tools, so nothing has to
be installed on the host and their versions move only when the pin does.

The rule this enforces: plaintext never reaches the nix store, a container image or
spawn's own state. `/nix/store` is world-readable and permanent, so a leak there is not
a bug you fix later. One test asserts exactly that — it encrypts a canary value, reads it
inside a running env, then greps for it across `/nix/store`, spawn's state directory and
the container's metadata. Staged plaintext is removed when the env stops.

Requires `XDG_RUNTIME_DIR` to be a tmpfs. If it isn't, spawn refuses rather than quietly
writing plaintext to disk.

## How an env is actually made

No base image, no Containerfile, no registry. A nix closure brings its own glibc, so
spawn mounts the host `/nix` **read-only** over an *empty* rootfs and puts the built
profile on `PATH`. Consequences worth knowing:

- Every env shares one store, so the Nth env from the same manifest costs ~0 extra disk.
- The store is read-only inside, so one env cannot corrupt another.
- There is no distro userland to inherit. `bashInteractive`, `coreutils` and `cacert`
  are always added (without `cacert` every TLS client in the env fails). `grep`, `sed`
  and `find` are not — they live in the `general` suite, because they are a preference
  rather than something spawn needs to function.

`nix` is in every env too, with the host's nix daemon socket bind-mounted in, so you can
add a package you turn out to need without leaving the box:

```
nix shell nixpkgs#cowsay --command cowsay hi
nix profile add --profile /root/.nix-profile nixpkgs#ripgrep
```

Writes go through the host daemon into the shared store. Anything you want *next time*
belongs in the manifest.

## Requirements

Rootless podman and a multi-user nix install on the host. Every command that needs one
checks for it first and tells you how to get it; `spawn doctor` checks the lot. Linux and WSL2 are the
supported hosts; macOS is unvalidated (see `../ROADMAP.md`).

**On Windows, spawn runs inside WSL2** — there is no native Windows build and there
should not be one: an env is a rootless podman container over a Linux nix store. The
source cross-compiles for `GOOS=windows`, but that binary would have no `/nix`, no
podman and no `/dev/net/tun`. Clone and build inside your WSL distro.

The repository can live on a Windows drive (`/mnt/c/...`) and build fine from there, but
**an env's rootfs cannot**. drvfs and 9p lack the ownership and xattr semantics a
container rootfs needs, and podman fails with
`container create failed (no logs from conmon)`, which names nothing you did. spawn
refuses up front instead, and `spawn doctor` reports the filesystem your env directory
sits on.

## Status

M1 is complete: `up`, `check`, `ls`, `stop`, `rm` and `profiles` all work on Linux and
WSL2. VPN, secrets, declared mounts and snapshots are later milestones — see
`../ROADMAP.md`.

`nixpkgs` is pinned to a **revision**, baked into the binary, so a manifest with no
`nixpkgs` field still rebuilds identically months later. The pin moves when you upgrade
spawn, not when nixpkgs does. Override it per manifest to pick another.

`persist` is the one thing that outlives the env. The rootfs already survives a restart
and a manifest change, so what `persist` buys is surviving `spawn rm` and a rebuild from
scratch — a tool upgrade should never cost you your notes. Its host storage sits outside
the env directory and mirrors the container layout, so you can browse it without spawn:

```
~/.local/share/spawn/persist/<env>/loot/...
```

`spawn rm` keeps it and tells you where it is; `spawn rm --purge` is the explicit way to
lose it. Entries are **directories** — podman creates a host directory for a missing bind
source, so a single file would silently become one; persist its parent instead.

A test asserts both halves of this: declared data survives `rm` and a rebuild, and
undeclared data does not — otherwise the env is not disposable.
