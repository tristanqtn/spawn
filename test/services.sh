#!/usr/bin/env bash
# Can an env run the SERVICES a tool needs, not just the tool?
#
# M5's third exit criterion is that "packaged" and "working in a container" are
# distinguished, with BloodHound CE as the example because it needs postgres and neo4j
# alongside it. Saying that in a comment is cheap. This proves the services themselves
# run inside one env, and records exactly where BloodHound CE still stops.
#
# The interesting one is postgres: it REFUSES to run as root, and an env runs as root.
# setpriv drops to another uid without needing a setuid binary, because we are already
# root -- so a database in an env is a declared user plus setpriv, and nothing more.
#
# Usage: test/services.sh      (needs spawn on PATH, podman, and a nix store)
set -u
R=${SPAWN_TEST_DIR:-$HOME/.cache/spawn-services-test}
rm -rf "$R"; mkdir -p "$R"; cd "$R" || exit 1
exec > >(tee "$R/run.log") 2>&1

fail=0
ok()   { printf '  [PASS] %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=1; }
note() { printf '  ..... %s\n' "$1"; }

ENV=svclab
cleanup() { spawn rm --purge "$ENV" >/dev/null 2>&1; }
[ "${SPAWN_KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup

cat > svclab.toml <<'EOF'
schema = 1
name = "svclab"
tools = ["postgresql", "neo4j", "openjdk", "bloodhound-ce", "util-linux",
         "curl", "coreutils", "gnugrep", "which", "bashInteractive"]

# postgres will not run as root, so it needs a uid of its own. Declared, not appended
# by a hook: declared files are authoritative and rewritten on every up.
[files]
"/etc/passwd" = { content = '''
root:x:0:0:root:/root:/bin/sh
postgres:x:70:70:postgres:/var/lib/postgresql:/bin/sh
nobody:x:65534:65534:nobody:/:/sbin/nologin
''' }
"/etc/group" = { content = '''
root:x:0:
postgres:x:70:
nogroup:x:65534:
''' }
EOF

printf 'building the env\n'
spawn up svclab.toml true >/dev/null 2>&1 || { echo "the env did not build"; exit 1; }

# --- postgres ---------------------------------------------------------------------
printf '\n== postgres, as a non-root uid\n'
spawn up "$ENV" bash -c '
  set -e
  mkdir -p /bin /var/lib/postgresql/data /run/postgresql
  [ -e /bin/sh ] || ln -s "$SPAWN_PROFILE/bin/bash" /bin/sh
  chown -R 70:70 /var/lib/postgresql /run/postgresql
  if [ ! -f /var/lib/postgresql/data/PG_VERSION ]; then
    setpriv --reuid=70 --regid=70 --clear-groups \
      initdb -D /var/lib/postgresql/data -U postgres --auth=trust >/dev/null
  fi
  setpriv --reuid=70 --regid=70 --clear-groups \
    pg_ctl -D /var/lib/postgresql/data -l /var/lib/postgresql/pg.log \
    -o "-k /run/postgresql -h 127.0.0.1 -p 5432" start >/dev/null
' >/dev/null 2>&1

pg=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  pg=$(spawn up "$ENV" bash -c 'psql -h 127.0.0.1 -U postgres -tAc "select 1" 2>/dev/null' 2>/dev/null | tr -d ' \r')
  [ "$pg" = 1 ] && break
  sleep 2
done
if [ "$pg" = 1 ]; then
  ok "postgres runs in an env and answers a query"
  note "$(spawn up "$ENV" bash -c 'psql -h 127.0.0.1 -U postgres -tAc "select version()"' 2>/dev/null | cut -c1-60)"
else
  bad "postgres did not answer (got '$pg')"
  note "$(spawn up "$ENV" bash -c 'tail -3 /var/lib/postgresql/pg.log' 2>/dev/null | tr '\n' ' ')"
fi

# A database for an application to use, which is the point of having postgres at all.
spawn up "$ENV" bash -c '
  psql -h 127.0.0.1 -U postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='"'"'bloodhound'"'"'" | grep -q 1 ||
    psql -h 127.0.0.1 -U postgres -c "CREATE USER bloodhound WITH PASSWORD '"'"'bloodhoundpw'"'"'" >/dev/null
  psql -h 127.0.0.1 -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='"'"'bloodhound'"'"'" | grep -q 1 ||
    psql -h 127.0.0.1 -U postgres -c "CREATE DATABASE bloodhound OWNER bloodhound" >/dev/null
' >/dev/null 2>&1
db=$(spawn up "$ENV" bash -c 'psql -h 127.0.0.1 -U postgres -tAc "SELECT datname FROM pg_database WHERE datname='"'"'bloodhound'"'"'"' 2>/dev/null | tr -d ' \r')
[ "$db" = bloodhound ] && ok "a role and database can be created for an application" \
  || bad "could not create the application database (got '$db')"

# --- neo4j ------------------------------------------------------------------------
# The package is read-only in the store, so NEO4J_HOME has to be a writable copy.
printf '\n== neo4j, from a writable NEO4J_HOME\n'
spawn up "$ENV" bash -c '
  set -e
  if [ ! -d /var/lib/neo4j/bin ]; then
    mkdir -p /var/lib/neo4j
    cp -r "$SPAWN_PROFILE/share/neo4j"/. /var/lib/neo4j/
    chmod -R u+w /var/lib/neo4j
  fi
  export NEO4J_HOME=/var/lib/neo4j
  # The stock neo4j.conf already serves bolt on 127.0.0.1:7687. Appending those
  # settings again is not harmless -- neo4j refuses to start with
  # "server.http.enabled declared multiple times".
  neo4j-admin dbms set-initial-password neo4jpassword >/dev/null 2>&1 || true
  neo4j start >/dev/null 2>&1
' >/dev/null 2>&1

bolt=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  bolt=$(spawn up "$ENV" bash -c 'export NEO4J_HOME=/var/lib/neo4j; timeout 20 cypher-shell -a bolt://127.0.0.1:7687 -u neo4j -p neo4jpassword "RETURN 1 AS ok;" 2>/dev/null | tail -1' 2>/dev/null | tr -d ' \r')
  [ "$bolt" = 1 ] && break
  sleep 5
done
[ "$bolt" = 1 ] && ok "neo4j runs in an env and answers over bolt" \
  || bad "neo4j did not answer over bolt (got '$bolt')"

# --- BloodHound CE, as far as it goes ---------------------------------------------
# This is the honest part. It gets further than anyone had checked -- all the way
# through its SQL migrations -- and then stops on a Neo4j version mismatch.
printf '\n== BloodHound CE against those services\n'
spawn up "$ENV" bash -c '
  mkdir -p /etc/bhapi /opt/bhapi/work /opt/bhapi/collectors /var/log
  cat > /etc/bhapi/bhapi.json <<JSON
{
  "version": 1,
  "bind_addr": "127.0.0.1:8080",
  "metrics_port": ":2112",
  "root_url": "http://127.0.0.1:8080/",
  "work_dir": "/opt/bhapi/work",
  "log_level": "INFO",
  "log_path": "/var/log/bhapi.log",
  "collectors_base_path": "/opt/bhapi/collectors",
  "tls": { "cert_file": "", "key_file": "" },
  "database": { "addr": "127.0.0.1:5432", "username": "bloodhound", "secret": "bloodhoundpw", "database": "bloodhound" },
  "neo4j": { "addr": "127.0.0.1:7687", "username": "neo4j", "secret": "neo4jpassword" },
  "default_admin": { "principal_name": "admin", "password": "Bloodhound123!", "email_address": "admin@example.com", "first_name": "Admin", "last_name": "User", "expire_now": false },
  "crypto": { "jwt": { "signing_key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" }, "argon2": { "memory_kibibytes": 1024, "num_iterations": 1, "num_threads": 1 } },
  "enable_cypher_mutations": false,
  "graph_query_memory_limit": 2,
  "recreate_default_admin": false
}
JSON
' >/dev/null 2>&1

# tail -12, not -3: on a second run there are no NEW migrations, so the line that
# proves postgres worked ("No new SQL migrations to run") sits above the banner and the
# neo4j error, and a 3-line window misses it.
bh=$(spawn up "$ENV" bash -c 'export NEO4J_HOME=/var/lib/neo4j; timeout 40 bloodhound-ce -configfile /etc/bhapi/bhapi.json 2>&1 | tail -12' 2>/dev/null)
case "$bh" in
  *"No new SQL migrations"*|*"Executing SQL migrations"*)
    ok "BloodHound CE connects to postgres and runs its migrations" ;;
  *) bad "BloodHound CE did not reach its migrations: $(printf '%s' "$bh" | tr '\n' ' ' | cut -c1-200)" ;;
esac

# The known blocker, asserted as the known blocker. If this ever STOPS matching, the
# incompatibility is gone and the note in profiles/active-directory.toml is stale --
# which is worth being told about.
case "$bh" in
  *db.indexes*|*ProcedureNotFound*)
    ok "and stops on the documented Neo4j 4.4 incompatibility, as expected"
    note "bloodhound-ce 8.3.1 calls db.indexes, removed after Neo4j 4.4; the pin has 2026.10.2" ;;
  *"Started server"*|*"Server started"*)
    bad "BloodHound CE now STARTS: the Neo4j note is stale, update it" ;;
  *) note "unrecognised outcome: $(printf '%s' "$bh" | tr '\n' ' ' | cut -c1-200)" ;;
esac

printf '\n'
[ "$fail" -eq 0 ] && printf 'SERVICES OK: postgres and neo4j both run inside one env.\n' \
                  || printf 'SERVICES INCOMPLETE: see the failures above.\n'
exit "$fail"
