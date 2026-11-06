# spawn

Declarative, disposable environments. One file describes a box; spawn builds it
reproducibly and runs it anywhere — for you or for your agent.

```toml
# spawn.toml
schema = 1
name = "lab"
profiles = ["general", "active-directory"]
tools = ["masscan"]
```

```
spawn up            # build and drop into a shell
spawn check         # evaluate the manifest, download nothing
spawn profiles      # list the built-in suites
```

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
nixpkgs, and an unfree package in a default suite breaks every build of it until a
manifest can opt in. Add them by hand once that field exists.

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

M1 walking skeleton. `up`, `check` and `profiles` work; the env is ephemeral, and
`ls`/`stop`/`rm`/VPN/secrets/snapshots are later milestones.
