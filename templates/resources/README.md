# resources — your own scripts, wordlists and notes

This is spawn's answer to Exegol's `my-resources`: a directory from the host, mounted
into the env, holding the things that are *yours* and should outlive any single
environment.

The manifest mounts it read-only at `/opt/resources`:

```toml
mounts = ["./resources:/opt/resources:ro"]
```

Read-only on purpose. A tool that can rewrite your wordlists and helper scripts turns
one bad command in a disposable box into a change on your real machine, and the whole
point of a disposable box is that it cannot do that. Drop the `:ro` if you want the
env to write here, knowing what it costs.

## Where things go

| Path | For |
|---|---|
| `bin/` | your own scripts. Add `/opt/resources/bin` to PATH via `[shell] init`. |
| `wordlists/` | the lists you actually use, as opposed to all of seclists. |
| `payloads/` | revshells, templates, the one XXE that always works. |
| `notes/` | methodology, checklists, client-specific gotchas. |

Nothing enforces this layout. It is a starting point, and the only thing spawn knows
about it is the mount line in the manifest.

## Sharing it between environments

One directory, mounted into every env, is the point. Keep it in git — it is yours, and
it is the part you would actually miss.

```toml
# in any manifest, anywhere on the host
mounts = ["~/spawn-resources:/opt/resources:ro"]
```

A relative path is resolved against the manifest, so `./resources` works for a
per-project set and `~/spawn-resources` for the set you carry everywhere.

## What does NOT belong here

Secrets. Use `[secrets]`, which decrypts to a tmpfs at `/run/secrets` and keeps the
plaintext out of the nix store, out of container metadata and off disk. A VPN config
or an SSH key in a mounted directory is a plaintext secret with extra steps.

## Loot goes the other way

This directory is input. For output — the loot, the scans, the notes you take *during*
the engagement — use `persist`, which survives `spawn rm` and a rebuild:

```toml
persist = ["/loot", "/root/.local/state"]
```

A tool upgrade should never cost you your findings.
