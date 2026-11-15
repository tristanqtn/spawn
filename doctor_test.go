package main

import "testing"

func TestShortRev(t *testing.T) {
	for ref, want := range map[string]string{
		"github:NixOS/nixpkgs/d5cc6833999746cffdfe0598f7bc801a57b887a9": "d5cc683",
		"github:NixOS/nixpkgs/nixos-unstable":                           "nixos-unstable",
		"github:NixOS/nixpkgs/abc":                                      "abc",
		"flake:local":                                                   "flake:local",
	} {
		if got := shortRev(ref); got != want {
			t.Errorf("shortRev(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestLimitField(t *testing.T) {
	// The cgroup controller is "cpu" but the manifest field is "cpus"; reporting the
	// controller name would send the user looking for a field that does not exist.
	if limitField("cpu") != "cpus" {
		t.Error("cpu controller should map to the limits.cpus field")
	}
	for _, c := range []string{"memory", "pids"} {
		if limitField(c) != c {
			t.Errorf("%s should map to itself", c)
		}
	}
}
