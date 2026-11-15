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

Rootless podman and a multi-user nix install on the host. Linux and WSL2 are the
supported hosts; macOS is unvalidated (see `../ROADMAP.md`).

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
