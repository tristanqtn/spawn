# hashcat 8.0.0.
#
# nixpkgs ships 7.1.2 on both the pin and unstable; upstream released 8.0.0 on
# 2026-10-25. This is the one genuine packaging gap W0.6 found, and it is still open.
#
# An overrideAttrs rather than a derivation of our own: nixpkgs' build is correct and
# 8.0.0 did not change it, so copying 130 lines to bump two would be 130 lines to keep
# in sync. BOTH attributes have to move together -- upstream's src url interpolates
# finalAttrs.version, so bumping the version alone would fetch 8.0.0 and check it
# against 7.1.2's hash.
#
# Delete this file when nixpkgs catches up. `spawn doctor` says when that happens.
final: prev:
prev.hashcat.overrideAttrs (old: {
  version = "8.0.0";
  src = prev.fetchurl {
    url = "https://hashcat.net/files/hashcat-8.0.0.tar.gz";
    hash = "sha256-1qdTPh4lCiNqi5nQtyXN122P3OdEx+6ssr9CIQ/kdhs=";
  };

  # 8.0.0 dropped the hardcoded /usr/bin/ar that nixpkgs' postPatch rewrites, and
  # --replace-fail is -- correctly -- fatal when its pattern is absent, so the stock
  # patch phase fails on the new source. The other three hardcoded darwin paths are
  # still there, so they keep --replace-fail rather than being quietly skipped: a
  # pattern that stops matching should break the build, not the resulting binary.
  postPatch = ''
    substituteInPlace src/Makefile \
      --replace-fail "export MACOSX_DEPLOYMENT_TARGET" "#export MACOSX_DEPLOYMENT_TARGET" \
      --replace-fail "/usr/bin/sed" "sed" \
      --replace-fail '-i ""' '-i'
  '';

  # 8.0.0 ships its Markov statistics xz-compressed and dlopens liblzma to read them.
  # A dlopen by soname does not get a RUNPATH entry -- nothing links it at build time --
  # so adding xz to buildInputs would change nothing. The library has to be on
  # LD_LIBRARY_PATH, which is why this extends the wrapper nixpkgs already installs
  # instead of adding an input.
  #
  # Without it hashcat starts, prints "xz support is unavailable", and refuses every
  # attack mode that uses Markov statistics -- which is the default for -a 3. It would
  # have passed a `--version` smoke check while being useless.
  postFixup = (old.postFixup or "") + ''
    wrapProgram $out/bin/hashcat \
      --prefix LD_LIBRARY_PATH : ${prev.lib.makeLibraryPath [ prev.xz.out ]}
  '';
})
