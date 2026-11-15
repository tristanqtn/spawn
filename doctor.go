package main

// spawn doctor. Three of the W0 spike's debug cycles went to kernel and runtime errors
// that name nothing useful: ping failing AT EXEC with "Operation not permitted",
// nmap dying with "dnet: Failed to open device eth0", and a cgroup write refused with
// "Invalid argument". Every check here therefore ends in the manifest field or host
// action that fixes it -- a diagnostic that only says "broken" would have saved nobody.

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
)

type result int

const (
	ok result = iota
	warn
	bad
)

func (r result) String() string {
	switch r {
	case ok:
		return "ok"
	case warn:
		return "warn"
	}
	return "FAIL"
}

type check struct {
	name   string
	state  result
	detail string // what was found, or the field/action that fixes it
}

func doctor(manifestPath string) error {
	var cs []check
	add := func(name string, state result, format string, a ...any) {
		cs = append(cs, check{name, state, fmt.Sprintf(format, a...)})
	}

	// --- the runtime -------------------------------------------------------------
	if v, err := podmanOut("version", "-f", "{{.Client.Version}}"); err != nil {
		add("podman", bad, "not found: spawn needs rootless podman")
	} else {
		add("podman", ok, "%s", v)
		if r, _ := podmanOut("info", "-f", "{{.Host.Security.Rootless}}"); r != "true" {
			add("rootless", warn, "podman is running as root; spawn is designed for rootless")
		} else {
			add("rootless", ok, "yes")
		}
	}
	if _, err := exec.LookPath("newuidmap"); err != nil {
		add("newuidmap", bad, "missing: install uidmap, or rootless containers cannot start")
	} else if err := subidConfigured(); err != nil {
		add("subuid/subgid", bad, "%s", err)
	} else {
		add("subuid/subgid", ok, "configured")
	}

	// The spike lost three test results to this and the error names only newuidmap.
	if u, err := user.Current(); err == nil {
		if gid := strconv.Itoa(os.Getgid()); gid != u.Gid {
			add("process group", bad,
				"running under sg/newgrp (gid %s, login gid %s): rootless podman refuses this; run spawn from a normal shell",
				gid, u.Gid)
		} else {
			add("process group", ok, "login gid")
		}
	}

	// --- cgroups, which is what limits.* depends on ------------------------------
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		add("cgroup v2", bad, "no unified hierarchy: limits.cpus/memory/pids will not apply")
	} else {
		add("cgroup v2", ok, "unified")
		delegated := delegatedControllers()
		for _, c := range []string{"cpu", "memory", "pids"} {
			if delegated[c] {
				add("limits."+limitField(c), ok, "%s controller delegated", c)
			} else {
				add("limits."+limitField(c), warn,
					"%s controller not delegated to this user; the limit will be ignored", c)
			}
		}
		if !delegated["io"] {
			// Expected on WSL2. Say so, so nobody goes looking for limits.io.
			add("limits.io", warn, "io controller not delegated (normal on WSL2); spawn has no limits.io field")
		}
	}

	// --- the things that make offensive tooling work -----------------------------
	if fi, err := os.Stat("/dev/net/tun"); err != nil {
		add("devices", warn,
			"/dev/net/tun absent: VPN envs will not work. Load the tun module, then declare devices = [\"/dev/net/tun\"]")
	} else {
		add("devices", ok, "/dev/net/tun present (%s); declare devices = [\"/dev/net/tun\"] to use it", fi.Mode().Perm())
	}
	// ping carries file capabilities a rootless userns will not grant, so it fails at
	// exec rather than at send. nmap -sS needs the same cap for raw sockets.
	add("caps", ok, "ping and nmap -sS need caps = [\"NET_RAW\"]; nftables and tunnels need NET_ADMIN")

	// --- nix ---------------------------------------------------------------------
	if _, err := exec.LookPath("nix"); err != nil {
		add("nix", bad, "not found: spawn builds every env from the host nix store")
	} else {
		v, _ := nixCmd("--version").Output()
		add("nix", ok, "%s", strings.TrimSpace(strings.TrimPrefix(string(v), "nix (Nix) ")))
		if _, err := os.Stat(nixDaemonSocket); err != nil {
			add("nix daemon", warn,
				"no socket at %s: nix inside an env will be read-only, so `nix shell` will not work there",
				nixDaemonSocket)
		} else {
			add("nix daemon", ok, "socket present, so nix works inside an env")
		}
	}

	// --- secrets -----------------------------------------------------------------
	if _, err := secretsStage("probe"); err != nil {
		add("secrets", bad, "%s", err)
	} else {
		add("secrets", ok, "XDG_RUNTIME_DIR available for tmpfs staging")
	}

	// --- the manifest, if one was named ------------------------------------------
	if manifestPath != "" {
		cs = append(cs, manifestChecks(manifestPath)...)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	worst := ok
	for _, c := range cs {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.state, c.name, c.detail)
		if c.state > worst {
			worst = c.state
		}
	}
	w.Flush()
	if worst == bad {
		return fmt.Errorf("at least one check failed")
	}
	return nil
}

func limitField(controller string) string {
	if controller == "cpu" {
		return "cpus"
	}
	return controller
}

// delegatedControllers reads the controllers this user's cgroup may actually set.
// A limit in the manifest that the kernel silently ignores is worse than no limit.
func delegatedControllers() map[string]bool {
	out := map[string]bool{}
	// The leaf the user's containers land in is what matters, not the root.
	for _, p := range []string{
		fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/cgroup.controllers", os.Getuid()),
		"/sys/fs/cgroup/cgroup.controllers",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, c := range strings.Fields(string(b)) {
			out[c] = true
		}
		break
	}
	return out
}

func subidConfigured() error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	for _, f := range []string{"/etc/subuid", "/etc/subgid"} {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("%s unreadable: %v", f, err)
		}
		if !strings.Contains(string(b), u.Username+":") {
			return fmt.Errorf("no entry for %s in %s; run: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 %s",
				u.Username, f, u.Username)
		}
	}
	return nil
}

// manifestChecks validates one manifest against this host: the things that are fine
// in the file but wrong here.
func manifestChecks(path string) []check {
	b, err := os.ReadFile(path)
	if err != nil {
		return []check{{"manifest", bad, err.Error()}}
	}
	m, err := Parse(b)
	if err != nil {
		return []check{{"manifest", bad, err.Error()}}
	}
	cs := []check{{"manifest", ok, fmt.Sprintf("%s, %d packages, nixpkgs %s",
		m.Name, len(m.resolved), shortRev(m.Nixpkgs))}}

	if err := m.validateHostPaths(filepath.Dir(path)); err != nil {
		cs = append(cs, check{"manifest paths", bad, err.Error()})
	} else {
		cs = append(cs, check{"manifest paths", ok, "every mount and device exists"})
	}

	// Tools that need NET_RAW are the commonest opaque failure in the spike, so say
	// it before the user hits "Operation not permitted" at exec.
	declared := map[string]bool{}
	for _, c := range m.Caps {
		declared[c] = true
	}
	for _, t := range m.resolved {
		if (t == "nmap" || t == "iputils" || t == "masscan" || t == "bettercap") && !declared["NET_RAW"] {
			cs = append(cs, check{"caps", warn, fmt.Sprintf(
				"%s needs raw sockets; without caps = [\"NET_RAW\"] it fails with an error naming nothing useful", t)})
			break
		}
	}
	if _, err := m.check(); err != nil {
		cs = append(cs, check{"evaluates", bad, "nix cannot evaluate this manifest; run spawn check for the reason"})
	} else {
		cs = append(cs, check{"evaluates", ok, "nix evaluates it"})
	}
	return cs
}

// shortRev abbreviates a 40-character git revision and leaves anything else alone:
// truncating a branch name would turn "nixos-unstable" into "nixos-u", which reads
// like a revision and is not one.
func shortRev(ref string) string {
	i := strings.LastIndex(ref, "/")
	if i < 0 {
		return ref
	}
	last := ref[i+1:]
	if len(last) != 40 || strings.TrimLeft(last, "0123456789abcdef") != "" {
		return last
	}
	return last[:7]
}
