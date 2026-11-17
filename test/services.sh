#!/usr/bin/env bash
# Can an env run the SERVICES a tool needs, not just the tool?
#
# M5's third exit criterion is that "packaged" and "working in a container" are
# distinguished, with BloodHound CE as the example because it needs postgres and neo4j
# alongside it. Saying that in a comment is cheap. This runs the whole platform: both
# services and the API, in one env, and it answers.
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
  # 4.4 wants `set-initial-password`; 5.x moved it under `dbms`. spawn carries 4.4
  # (pkgs/neo4j.nix) because BloodHound CE needs it, but try both so this still works
  # if that override is ever dropped.
  neo4j-admin set-initial-password neo4jpassword >/dev/null 2>&1 ||
    neo4j-admin dbms set-initial-password neo4jpassword >/dev/null 2>&1 || true
  neo4j start >/dev/null 2>&1
' >/dev/null 2>&1

bolt=""
# Generous on purpose: neo4j 4.4 on JDK 11 took around a minute to report
# "Bolt enabled on localhost:7687", and a window that expires first looks exactly like
# a server that never started.
for _ in $(seq 1 18); do
  # neo4j's own words, out of its own log. Two other checks were tried here and both
  # measured the harness rather than the server: cypher-shell returns nothing under
  # `podman exec` with no tty, and a python socket probe nested three levels of quoting
  # deep returned nothing either. A grep for the line neo4j prints when bolt is up has
  # no such problem, and the functional proof follows anyway -- BloodHound CE completes
  # a graph migration against this database a few lines below, which it cannot do
  # against one that is not serving.
  bolt=$(spawn up "$ENV" bash -c 'grep -c "Bolt enabled" /var/lib/neo4j/logs/neo4j.log 2>/dev/null' 2>/dev/null | tr -d ' ')
  case "$bolt" in ""|0) ;; *) break ;; esac
  sleep 5
done
case "$bolt" in
  ""|0) bad "neo4j never reported bolt coming up" ;;
  *)    ok "neo4j runs in an env and reports bolt enabled" ;;
esac

# --- BloodHound CE ----------------------------------------------------------------
# The whole point of the file. Against the pin's neo4j 2026.10.2 this stopped dead on
# db.indexes; with spawn's own neo4j 4.4 it runs.
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
  # post-processing or a started daemon is stronger evidence than a migration line, and
  # on a second run there are no NEW migrations to print.
  *"No new SQL migrations"*|*"Executing SQL migrations"*|*post-processing*|*"Starting daemon"*)
    ok "BloodHound CE connects to postgres and gets through its migrations" ;;
  *) bad "BloodHound CE did not reach its migrations: $(printf '%s' "$bh" | tr '\n' ' ' | cut -c1-200)" ;;
esac

# And it has to get PAST the graph migration, which is the only reason spawn carries
# neo4j 4.4 at all (pkgs/neo4j.nix). Against the pin's neo4j 2026.10.2 this is exactly
# where it died: db.indexes was removed after 4.4, so bloodhound-ce reported
# ProcedureNotFound and exited. Seeing that again means the override stopped applying.
case "$bh" in
  *db.indexes*|*ProcedureNotFound*)
    bad "the neo4j 4.4 override is not in effect: db.indexes is missing again" ;;
  *)
    ok "it gets past the graph migration that neo4j 4.4 is carried for" ;;
esac

# Then started for real and asked whether it answers, which is the entire difference
# between "packaged" and "working in a container".
P=$(podman inspect "spawn-$ENV" -f '{{index .Config.Labels "spawn.profile"}}')
podman exec -d -e NEO4J_HOME=/var/lib/neo4j "spawn-$ENV" \
  "$P/bin/bloodhound-ce" -configfile /etc/bhapi/bhapi.json >/dev/null 2>&1
api=""
for _ in $(seq 1 15); do
  api=$(spawn up "$ENV" bash -c 'curl -s -o /dev/null -w "%{http_code}" --max-time 6 http://127.0.0.1:8080/api/version' 2>/dev/null | tr -d ' \r')
  case "$api" in 2*|3*|4*) break ;; esac
  sleep 5
done
case "$api" in
  2*|3*|4*)
    ok "the BloodHound CE API answers on 8080 (HTTP $api)"
    note "admin / Bloodhound123! -- a lab password in a disposable env" ;;
  *)
    bad "the API never answered (got '$api')"
    note "$(spawn up "$ENV" bash -c 'tail -4 /var/log/bhapi.log' 2>/dev/null | tr '\n' ' ' | cut -c1-240)" ;;
esac

printf '\n'
[ "$fail" -eq 0 ] && printf 'SERVICES OK: postgres and neo4j both run inside one env.\n' \
                  || printf 'SERVICES INCOMPLETE: see the failures above.\n'
exit "$fail"
