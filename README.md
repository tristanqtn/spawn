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
caps    = ["NET_ADMIN", "NET_RAW"]
devices = ["/dev/net/tun"]

[limits]
cpus = "2"
memory = "4g"
pids = 512

[hooks]
post_start = ["echo ready > /root/.ready"]
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
spawn up            # build an env and enter it (reuses it if it exists)
spawn check         # evaluate the manifest, download nothing
spawn ls            # list envs
spawn stop <name>   # stop an env, keeping its rootfs
spawn rm <name>     # destroy an env and its rootfs
spawn profiles      # list the built-in suites
```

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

Rootless podman and a multi-user nix install on the host. Linux and WSL2 are the
supported hosts; macOS is unvalidated (see `../ROADMAP.md`).

## Status

M1 is complete: `up`, `check`, `ls`, `stop`, `rm` and `profiles` all work on Linux and
WSL2. VPN, secrets, declared mounts and snapshots are later milestones — see
`../ROADMAP.md`.

`nixpkgs` is pinned to a **revision**, baked into the binary, so a manifest with no
`nixpkgs` field still rebuilds identically months later. The pin moves when you upgrade
spawn, not when nixpkgs does. Override it per manifest to pick another.

Still rough: the whole rootfs persists, but nothing is yet declarable as persistent in
the manifest.
