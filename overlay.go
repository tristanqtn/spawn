package main

// Packages spawn maintains itself, as overlay fragments over the pinned nixpkgs.
//
// This exists for one reason: nixpkgs is sometimes behind on a tool that matters, and
// "wait for nixpkgs" is not an answer when the tool is the job. hashcat is the standing
// example -- 7.1.2 in nixpkgs against 8.0.0 upstream.
//
// Each pkgs/<attr>.nix is an overlay fragment: a `final: prev:` function returning the
// package that should replace prev.<attr>. They are inlined into the generated
// expression rather than written to disk, because the expression already travels as a
// string and a temp file would be one more thing to clean up and one more path to get
// wrong.
//
// An override applies ONLY when the manifest actually resolved that attribute. A
// manifest with no hashcat should not pay hashcat's eval cost, and more importantly a
// broken fragment should not be able to break an unrelated env.
//
// This is also the seam W10 grows: a contributor adds one file here, and CI builds only
// what changed. The shape is deliberately the smallest thing that supports that.

import (
	"embed"
	"fmt"
	"path"
	"sort"
	"strings"
)

//go:embed pkgs/*.nix
var pkgFS embed.FS

// overrideNames lists the attributes spawn maintains, sorted so the generated
// expression is stable -- the config fingerprint is a hash of it.
func overrideNames() []string {
	es, _ := pkgFS.ReadDir("pkgs")
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(e.Name(), ".nix"))
	}
	sort.Strings(out)
	return out
}

// overlayFor returns the nix overlay for the attributes this manifest resolved, or ""
// when it uses none of them. The empty case matters: it keeps every existing manifest's
// expression byte-identical, so adding this file does not invalidate a single
// fingerprint or force a rebuild.
func (m *Manifest) overlayFor() string {
	want := make(map[string]bool, len(m.resolved))
	for _, t := range m.resolved {
		want[t] = true
	}
	var b strings.Builder
	for _, name := range overrideNames() {
		if !want[name] {
			continue
		}
		src, err := pkgFS.ReadFile(path.Join("pkgs", name+".nix"))
		if err != nil {
			continue
		}
		// The fragment is a function of (final, prev); applying it here rather than
		// in the file keeps each file a plain overlay fragment a contributor can read
		// and a reviewer can diff.
		fmt.Fprintf(&b, "    %s = (\n%s\n    ) final prev;\n", name, string(src))
	}
	if b.Len() == 0 {
		return ""
	}
	return "  overlays = [ (final: prev: {\n" + b.String() + "  }) ];\n"
}

// overriddenBy reports which spawn-maintained attributes a manifest is using, for
// `spawn check` and `spawn doctor` to say so out loud. An override is debt: the user
// should know they are not running stock nixpkgs.
func (m *Manifest) overriddenBy() []string {
	want := make(map[string]bool, len(m.resolved))
	for _, t := range m.resolved {
		want[t] = true
	}
	var out []string
	for _, name := range overrideNames() {
		if want[name] {
			out = append(out, name)
		}
	}
	return out
}
