package main

// Preflight checks for the two host dependencies.
//
// These exist because the alternative is worse than an ugly error. Without this,
// `spawn stop` with podman absent reported `no env named "lab"` for a running env,
// and `spawn rm` reported success while deleting the rootfs of a container it had
// never managed to remove. The cause was inspect() treating "podman says no such
// container" and "podman could not be run" as the same answer. Every command that
// shells out now refuses up front, so inspect()'s empty result can only mean the
// container genuinely does not exist.

import (
	"fmt"
	"os/exec"
)

type dep struct{ bin, why string }

var (
	depPodman = dep{"podman", "spawn runs every env in a rootless podman container.\n" +
		"       Debian/Ubuntu: sudo apt install podman"}
	depNix = dep{"nix", "spawn builds every env from the host nix store.\n" +
		"       Install: https://nixos.org/download (the multi-user/daemon install)"}
)

func (d dep) require() error {
	if _, err := exec.LookPath(d.bin); err != nil {
		return fmt.Errorf("%s is not installed, or not on PATH.\n       %s\n"+
			"       Run `spawn doctor` to check everything spawn needs", d.bin, d.why)
	}
	return nil
}

// requireDeps checks each dependency in turn, reporting the first that is missing.
func requireDeps(ds ...dep) error {
	for _, d := range ds {
		if err := d.require(); err != nil {
			return err
		}
	}
	return nil
}
