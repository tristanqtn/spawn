# neo4j 4.4.48, because BloodHound CE needs it.
#
# nixpkgs ships neo4j 2026.10.2. BloodHound CE 8.3.1 calls the `db.indexes` procedure,
# which Neo4j removed after 4.4, so against the stock package bloodhound-ce connects to
# postgres, runs every SQL migration, and then dies with:
#
#   Neo.ClientError.Procedure.ProcedureNotFound: There is no procedure with the name
#   `db.indexes` registered for this database instance.
#
# Measured, not inferred -- see test/services.sh, which asserts the whole chain. There
# is no 4.x under any attribute in the pin, so spawn carries it.
#
# This is a deliberate choice with a cost: a manifest asking for neo4j gets 4.4, not
# the latest. For spawn that is right -- neo4j is in the active-directory suite because
# BloodHound needs it, and a graph database that the tool using it cannot talk to is
# not a feature. Anyone wanting a modern neo4j should say so in `tools` against a
# nixpkgs without this overlay.
#
# Delete this file when BloodHound CE supports Neo4j 5+.
final: prev:
# The derivation takes its JDK as an argument, so swapping it needs no rewriting:
# 4.4 runs on Java 11 or 17 and refuses 25, which is what nixpkgs passes.
(prev.neo4j.override { openjdk25 = prev.jdk11; }).overrideAttrs (old: {
  version = "4.4.48";

  # dist.neo4j.org rather than the artifact.php redirect nixpkgs uses: the query-string
  # form does not serve 4.4 any more.
  src = prev.fetchurl {
    url = "https://dist.neo4j.org/neo4j-community-4.4.48-unix.tar.gz";
    hash = "sha256-+k9kBHz2AY+m+qICyDDT/2yNIVSuijMTySD8UEuqerI=";
  };

  # The install phase has to be restated for one line. nixpkgs ends it with
  # `neo4j-admin dbms set-initial-password`, and the `dbms` subcommand only exists from
  # 5.x -- on 4.4 the build fails there. Everything else is nixpkgs' own phase.
  installPhase = ''
    mkdir -p "$out/share/neo4j"
    cp -R * "$out/share/neo4j"

    mkdir -p "$out/bin"
    for NEO4J_SCRIPT in neo4j neo4j-admin cypher-shell
    do
        chmod +x "$out/share/neo4j/bin/$NEO4J_SCRIPT"
        makeWrapper "$out/share/neo4j/bin/$NEO4J_SCRIPT" \
            "$out/bin/$NEO4J_SCRIPT" \
            --prefix PATH : ${
              prev.lib.escapeShellArg (prev.lib.makeBinPath [
                prev.jdk11
                prev.which
                prev.gawk
              ])
            } \
            --set JAVA_HOME ${prev.jdk11}
    done

    patchShebangs $out/share/neo4j/bin/neo4j-admin

    # 4.4 syntax: no `dbms` subcommand. The password is replaced at first login, and
    # test/services.sh sets its own anyway.
    $out/bin/neo4j-admin set-initial-password neo4jadmin
  '';
})
