package main

import (
	"strings"
	"testing"
)

// The property that makes the overlay safe to add at all: a manifest that does not use
// a spawn-maintained package must generate the SAME expression as before. If it did
// not, adding one override would change every env's config fingerprint and force a
// rebuild of environments that have nothing to do with it.
func TestOverlayOnlyWhenUsed(t *testing.T) {
	plain, err := Parse([]byte("schema = 1\nname = \"p\"\ntools = [\"ripgrep\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := plain.overlayFor(); got != "" {
		t.Errorf("a manifest with no maintained package got an overlay:\n%s", got)
	}
	if strings.Contains(plain.expr(), "overlays") {
		t.Error("the expression mentions overlays when none apply")
	}
	if len(plain.overriddenBy()) != 0 {
		t.Errorf("overriddenBy reported %v", plain.overriddenBy())
	}

	// And a manifest that DOES use one gets it, with the attribute named.
	used, err := Parse([]byte("schema = 1\nname = \"p\"\ntools = [\"hashcat\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ov := used.overlayFor()
	if ov == "" {
		t.Fatal("hashcat is maintained by spawn but got no overlay")
	}
	if !strings.Contains(ov, "hashcat = (") {
		t.Errorf("the overlay does not bind hashcat:\n%s", ov)
	}
	if !strings.Contains(used.expr(), "overlays = [") {
		t.Error("the expression does not carry the overlay")
	}
	if got := used.overriddenBy(); len(got) != 1 || got[0] != "hashcat" {
		t.Errorf("overriddenBy = %v, want [hashcat]", got)
	}
}

// Each fragment has to be a `final: prev:` function, because that is how overlayFor
// applies it. A file that is a plain derivation would fail at eval with a type error
// pointing at generated code rather than at the file.
func TestOverlayFragmentsAreWellFormed(t *testing.T) {
	names := overrideNames()
	if len(names) == 0 {
		t.Skip("no spawn-maintained packages")
	}
	for _, n := range names {
		b, err := pkgFS.ReadFile("pkgs/" + n + ".nix")
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if !strings.Contains(src, "final: prev:") {
			t.Errorf("pkgs/%s.nix is not a `final: prev:` overlay fragment", n)
		}
		// A fragment that does not mention the attribute it replaces is almost
		// certainly a copy-paste of another one.
		if !strings.Contains(src, n) {
			t.Errorf("pkgs/%s.nix never mentions %q", n, n)
		}
		// It must say why it exists. An override is debt, and undocumented debt is
		// the kind nobody ever removes.
		if !strings.HasPrefix(strings.TrimSpace(src), "#") {
			t.Errorf("pkgs/%s.nix does not start with a comment explaining the override", n)
		}
	}
}

// An override must pin exactly what it fetches. A branch or a tag that moves would
// make two hosts build different binaries from the same manifest, which is the one
// property spawn exists to preserve.
func TestHashcatOverrideIsPinned(t *testing.T) {
	b, err := pkgFS.ReadFile("pkgs/hashcat.nix")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, `version = "8.0.0"`) {
		t.Error("the override does not name a concrete version")
	}
	if !strings.Contains(src, "hash = \"sha256-") {
		t.Error("the override does not pin a source hash")
	}
	// The URL has to interpolate nothing: upstream's own src uses finalAttrs.version,
	// and inheriting that while overriding only the hash is how you fetch 8.0.0 and
	// check it against 7.1.2's hash.
	if strings.Contains(src, "${finalAttrs.version}") || strings.Contains(src, "${old.version}") {
		t.Error("the override's url interpolates a version; write it literally")
	}
}

// pocl is the difference between hashcat being installed and hashcat working, and it
// only works if the loader is told where the ICD is. Without this an env cracks
// nothing while every binary reports fine.
func TestOpenCLVendorsSetWithPocl(t *testing.T) {
	with, err := Parse([]byte("schema = 1\nname = \"p\"\ntools = [\"hashcat\", \"pocl\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	argv, _, err := createArgs(with, "/nix/store/fake-profile", "/tmp/p.toml")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(argv, " ")
	if !strings.Contains(args, "OCL_ICD_VENDORS=/nix/store/fake-profile/etc/OpenCL/vendors") {
		t.Error("pocl is present but OCL_ICD_VENDORS is not set, so hashcat finds no device")
	}

	// And it is not set otherwise: an env with no OpenCL has no business carrying it.
	without, err := Parse([]byte("schema = 1\nname = \"p\"\ntools = [\"ripgrep\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	argv2, _, err := createArgs(without, "/nix/store/fake-profile", "/tmp/p.toml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(argv2, " "), "OCL_ICD_VENDORS") {
		t.Error("OCL_ICD_VENDORS is set in an env with no OpenCL")
	}
}
