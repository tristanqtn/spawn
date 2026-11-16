package main

// spawn smoke — does every tool in a suite actually RUN?
//
// This exists because of the one caveat W0.6 left standing: an attribute resolving in
// nixpkgs is not the same as the tool working in a container. `spawn check` proves the
// first. Only running the binary proves the second, and the gap between them is where
// the unpleasant surprises live -- a tool that needs a service, a device, a driver, or
// a $HOME it does not have.
//
// The default check for a tool is `command -v <attr>`, which is deliberately weak but
// catches the common failure: the attr installs nothing you can run, or installs it
// under a different name. A suite's [smoke] table overrides that per tool, and the
// override is where the real assertions go -- `hashcat --version | grep ^v8` is worth
// more than knowing a hashcat binary exists.
//
// Every tool gets one or the other, and nothing opts out: a tool with no entry falls
// back to the default rather than being skipped, so "every tool in the profile has a
// smoke check" is a property of the code, not a promise in a document.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// smokeChecks returns attr -> command for a suite and everything it includes, with the
// including suite's entries winning. The default is applied for anything the tables do
// not mention, so the result covers every tool in the resolved list.
func smokeChecks(profile string) (map[string]string, []string, error) {
	tools, err := profileTools(profile)
	if err != nil {
		return nil, nil, err
	}
	// baseTools are in every env whether a suite asks for them or not, and they are
	// not optional: a broken cacert breaks every TLS client in the box, and a missing
	// coreutils breaks the checks themselves. They belong in the coverage.
	tools = append(append([]string{}, baseTools...), tools...)
	explicit, err := smokeTable(profile, map[string]bool{})
	if err != nil {
		return nil, nil, err
	}
	// baseTools' checks live here rather than in a profile, because baseTools belong
	// to spawn and are present in every env. Putting them in general.toml made them
	// fail in every suite that does not include general -- and the default
	// `command -v bashInteractive` fails anyway, because the binary is called bash.
	for attr, check := range baseToolChecks {
		if _, ok := explicit[attr]; !ok {
			explicit[attr] = check
		}
	}
	out := make(map[string]string, len(tools))
	seen := make(map[string]bool, len(tools))
	var order []string
	for _, t := range tools {
		if seen[t] {
			continue
		}
		seen[t] = true
		order = append(order, t)
		if cmd, ok := explicit[t]; ok {
			out[t] = cmd
		} else {
			out[t] = defaultSmokeCheck(t)
		}
	}
	sort.Strings(order)
	return out, order, nil
}

// smokeTable collects the [smoke] tables of a suite and its includes. An outer suite
// overrides an inner one, which is what lets `pentest` fix up a check it inherits.
func smokeTable(name string, seen map[string]bool) (map[string]string, error) {
	if seen[name] {
		return nil, nil
	}
	seen[name] = true
	if !attrRe.MatchString(name) {
		return nil, fmt.Errorf("profile %q is not a bare name", name)
	}
	b, err := profileFS.ReadFile("profiles/" + name + ".toml")
	if err != nil {
		return nil, fmt.Errorf("no such profile %q", name)
	}
	var p profileFile
	if err := toml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	out := map[string]string{}
	for _, inc := range p.Includes {
		inner, err := smokeTable(inc, seen)
		if err != nil {
			return nil, err
		}
		for k, v := range inner {
			out[k] = v
		}
	}
	for k, v := range p.Smoke {
		out[k] = v
	}
	return out, nil
}

// smoke builds an env for the suite and runs every tool's check inside it.
func smoke(profile string, keep bool) error {
	checks, order, err := smokeChecks(profile)
	if err != nil {
		return err
	}
	env := "spawnsmoke" + strings.NewReplacer("-", "", "_", "", ".", "").Replace(profile)

	// The manifest is written to a real file because `up` records its path on the
	// container, and an env whose manifest never existed cannot be rebuilt.
	m, mpath, err := smokeManifest(profile, env)
	if err != nil {
		return err
	}
	if !keep {
		defer func() { _ = rm(env, true); _ = os.Remove(mpath) }()
	}
	fmt.Printf("building %s: %d tools\n", profile, len(order))
	if err := up(m, mpath, []string{"true"}); err != nil {
		return fmt.Errorf("the suite did not build: %w", err)
	}

	if ov := m.overriddenBy(); len(ov) > 0 {
		fmt.Printf("%s %s\n", ui.paint(ui.dim, "spawn-maintained packages in use:"),
			strings.Join(ov, ", "))
	}

	t := newTable("TOOL", "RESULT", "CHECK")
	var failed []string
	for _, tool := range order {
		out, err := execIn(env, smokeScript(checks[tool]))
		first := firstLine(out)
		if err != nil {
			failed = append(failed, tool)
			t.add(tool, ui.paint(ui.red, "FAIL"), truncate(first, 48))
			continue
		}
		t.add(tool, ui.paint(ui.green, "ok"), ui.paint(ui.dim, truncate(first, 48)))
	}
	t.print()
	fmt.Println()
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d tools failed their smoke check: %s",
			len(failed), len(order), strings.Join(failed, ", "))
	}
	fmt.Printf("%s all %d tools in %q run\n", ui.paint(ui.green, "ok"), len(order), profile)
	return nil
}

// smokeManifest writes the manifest a smoke run uses: the suite, no egress, and the
// privileges its tools need in order to be testable at all.
func smokeManifest(profile, env string) (*Manifest, string, error) {
	// NET_RAW because half of recon is raw sockets, and a tool that cannot open one
	// reports a permission error that looks exactly like a packaging failure.
	// Egress stays denied: a smoke check that reaches the internet is not a smoke
	// check, it is a scan.
	body := fmt.Sprintf("schema = 1\nname = %q\nprofiles = [%q]\n"+
		"allow_unfree = true\ncaps = [\"NET_RAW\"]\n\n[network]\negress = \"deny\"\n",
		env, profile)
	m, err := Parse([]byte(body))
	if err != nil {
		return nil, "", err
	}
	path := smokeManifestPath(env)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return nil, "", err
	}
	return m, path, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// smokeManifestPath keeps a smoke run's manifest beside the MCP server's, for the same
// reason: `up` records the path on the container, so it has to be a real file that
// survives the call.
func smokeManifestPath(env string) string { return "/tmp/spawn-smoke-" + env + ".toml" }

// profileNote returns a suite's note, resolving includes so a composed suite inherits
// what its parts require. Deduplicated and prefixed, because "pentest" inherits three.
func profileNotes(name string) ([]string, error) {
	return profileNotesSeen(name, map[string]bool{})
}

func profileNotesSeen(name string, seen map[string]bool) ([]string, error) {
	if seen[name] {
		return nil, nil
	}
	seen[name] = true
	if !attrRe.MatchString(name) {
		return nil, fmt.Errorf("profile %q is not a bare name", name)
	}
	b, err := profileFS.ReadFile("profiles/" + name + ".toml")
	if err != nil {
		return nil, fmt.Errorf("no such profile %q", name)
	}
	var p profileFile
	if err := toml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	var out []string
	for _, inc := range p.Includes {
		ns, err := profileNotesSeen(inc, seen)
		if err != nil {
			return nil, err
		}
		out = append(out, ns...)
	}
	if p.Note != "" {
		out = append(out, name+": "+p.Note)
	}
	return out, nil
}

// smokeScript wraps a check so its exit status actually means something.
//
// Both halves were learned the hard way. Without pipefail, `mp64 --version | head -1`
// reports success on the status of `head`, so a missing binary passed its smoke check
// while printing "mp64: command not found" in the very column meant to reassure you.
// Without errexit, only the last command in a multi-line check counts.
//
// A check may therefore not hide a failure behind a pipe, which is why the shipped
// tables prefer `command -v x` and a bare `x --version` over the prettier
// `x --version 2>&1 | head -1` -- the runner truncates the output for display anyway,
// so the pipe bought nothing and cost correctness.
func smokeScript(check string) string {
	return "set -eo pipefail\n" + check
}

// baseToolChecks covers the packages every env gets whether a suite asks or not.
// They are spawn's, not any profile's, so they cannot live in a profile file: put
// them in general.toml and they vanish from every suite that does not include it.
//
// Each one also shows why the default is not enough here: bashInteractive installs
// `bash`, cacert installs no binary at all, and coreutils installs hundreds.
var baseToolChecks = map[string]string{
	"bashInteractive": "bash --version",
	"coreutils":       "ls --version",
	// The one that matters most and is easiest to get wrong: without a readable
	// bundle at SSL_CERT_FILE, every TLS client in the env fails with an error that
	// names a certificate problem rather than a missing file.
	"cacert": `test -n "$SSL_CERT_FILE" && test -r "$SSL_CERT_FILE"`,
	"nix":    "nix --version",
	// iana-etc installs no binary. What matters is that spawn SEEDED its files into
	// the env's /etc, because that is the step that can go wrong -- the package was
	// in the closure for a build where seedBaseEtc silently ignored it, and fping
	// still failed with "icmp: unknown protocol".
	"iana-etc": "test -r /etc/protocols && test -r /etc/services",
}

// defaultSmokeCheck is what a tool gets when no table mentions it: the attr name
// doubles as the binary name for most of nixpkgs. Weak on purpose -- it still catches
// the common failure, which is an attr that installs nothing runnable or installs it
// under another name -- and it is what makes "every tool has a check" true without a
// table entry per tool.
func defaultSmokeCheck(attr string) string { return "command -v " + attr }
