package main

// The runtime surface: everything in the manifest that becomes a podman flag.
// Validation lives here and runs at parse time, because a typo that reaches podman
// produces an error naming a flag the user never wrote.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	capRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	// [host-ip:]host-port:container-port[/protocol]
	portRe   = regexp.MustCompile(`^(\[?[0-9a-fA-F.:]+\]?:)?\d{1,5}:\d{1,5}(/(tcp|udp|sctp))?$`)
	cpusRe   = regexp.MustCompile(`^\d+(\.\d+)?$`)
	memoryRe = regexp.MustCompile(`^\d+(\.\d+)?[kmgKMG]?[bB]?$`)
)

// validateRuntime checks every field that becomes a podman flag. Values always land
// after their own flag so none of them can be read as a flag, but a bad value here
// fails deep inside podman with a message that names nothing the user typed.
func (m *Manifest) validateRuntime() error {
	for k := range m.Env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("env key %q is not a shell-safe name", k)
		}
	}
	for _, mt := range m.Mounts {
		if _, _, err := splitMount(mt); err != nil {
			return err
		}
	}
	for _, p := range m.Ports {
		if !portRe.MatchString(p) {
			return fmt.Errorf("port %q is not host:container (e.g. \"8080:80\" or \"127.0.0.1:9001:9001\")", p)
		}
	}
	for _, c := range m.Caps {
		// Written as NET_ADMIN, not CAP_NET_ADMIN: podman accepts both, but one
		// spelling in the manifest means one spelling in the docs.
		if !capRe.MatchString(c) {
			return fmt.Errorf("cap %q should look like NET_ADMIN", c)
		}
	}
	for _, d := range m.Devices {
		if !strings.HasPrefix(d, "/dev/") {
			return fmt.Errorf("device %q must be a path under /dev", d)
		}
	}
	if m.Limits.CPUs != "" && !cpusRe.MatchString(m.Limits.CPUs) {
		return fmt.Errorf("limits.cpus %q should be a number like \"2\" or \"1.5\"", m.Limits.CPUs)
	}
	if m.Limits.Memory != "" && !memoryRe.MatchString(m.Limits.Memory) {
		return fmt.Errorf("limits.memory %q should look like \"4g\" or \"512m\"", m.Limits.Memory)
	}
	if m.Limits.PIDs < 0 {
		return fmt.Errorf("limits.pids cannot be negative")
	}
	for _, p := range m.Persist {
		if err := validPersistPath(p); err != nil {
			return err
		}
	}
	return nil
}

// Mounting over these would break the env rather than preserve anything: /nix is the
// shared store, and the rest are either kernel filesystems or the few directories the
// rootfs needs in order to start at all.
var unpersistable = []string{"/", "/nix", "/proc", "/sys", "/dev", "/etc", "/tmp"}

// validPersistPath checks one persist entry. Entries are DIRECTORIES: podman creates a
// host directory for a missing bind source, so a single file would silently become a
// directory and shadow itself. To keep one file, persist its parent.
func validPersistPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("persist %q must be an absolute path inside the env", p)
	}
	clean := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(p)), "/")
	if clean == "" {
		clean = "/"
	}
	for _, bad := range unpersistable {
		if clean == bad {
			return fmt.Errorf("persist %q: %s cannot be persisted, it is needed to start the env", p, bad)
		}
	}
	if strings.HasPrefix(clean, "/nix/") {
		return fmt.Errorf("persist %q: /nix is the shared store and is read-only by design", p)
	}
	return nil
}

// persistDir is where one env's persisted directories live on the host. It sits
// OUTSIDE envDir so that `spawn rm`, which deletes the rootfs, does not take it.
func persistDir(name string) string { return filepath.Join(dataDir(), "persist", name) }

// persistArgs creates the host side of each persisted directory and renders the mounts.
// The host layout mirrors the container's, so the data is browsable without spawn.
func (m *Manifest) persistArgs() ([]string, error) {
	var a []string
	for _, p := range m.Persist {
		clean := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(p)), "/")
		host := filepath.Join(persistDir(m.Name), strings.TrimPrefix(clean, "/"))
		if err := os.MkdirAll(host, 0o755); err != nil {
			return nil, err
		}
		a = append(a, "-v", filepath.ToSlash(host)+":"+clean)
	}
	return a, nil
}

// splitMount parses "host:container[:options]" into its host and container halves.
// A Windows drive letter is not a concern here: manifests describe Linux paths, and
// spawn only ever runs the container on a Linux host.
func splitMount(spec string) (host, rest string, err error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("mount %q is not host:container[:options]", spec)
	}
	target := strings.SplitN(parts[1], ":", 2)[0]
	if !strings.HasPrefix(target, "/") {
		return "", "", fmt.Errorf("mount %q: the container path must be absolute", spec)
	}
	return parts[0], parts[1], nil
}

// resolveHostPath makes a mount's host side absolute. Relative paths resolve against
// the MANIFEST's directory rather than the working directory, so a manifest means the
// same thing wherever it is run from -- which is the point of declaring it.
func resolveHostPath(p, manifestDir string) (string, error) {
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(manifestDir, p)
	}
	return filepath.ToSlash(filepath.Clean(p)), nil
}

// validateHostPaths checks EVERYTHING that depends on this host rather than on the
// manifest alone, and runs before the nix build. A profile can be gigabytes; finding
// out afterwards that a secret or a dotfile is missing throws that download away.
//
// Anything added here must be cheap and must not need the build's output. Decrypting
// a secret needs age from the pinned nixpkgs, so only the inputs are checked now --
// the encrypted file and the identity -- which is what a typo actually gets wrong.
func (m *Manifest) validateHostPaths(manifestDir string) error {
	if err := m.validateMountsAndDevices(manifestDir); err != nil {
		return err
	}
	if err := m.validateSecretSources(manifestDir); err != nil {
		return err
	}
	return m.validateFileSources(manifestDir)
}

// validateSecretSources checks each encrypted file and the identity needed to open it.
func (m *Manifest) validateSecretSources(manifestDir string) error {
	secs, err := m.secretList()
	if err != nil {
		return err
	}
	needAge := false
	for _, s := range secs {
		src, err := resolveHostPath(s.path, manifestDir)
		if err != nil {
			return err
		}
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("secret %q: %s does not exist", s.name, src)
		}
		if s.kind == "age" {
			needAge = true
		}
	}
	if needAge {
		if _, err := ageIdentity(); err != nil {
			return fmt.Errorf("secrets: %w", err)
		}
	}
	return nil
}

// validateFileSources checks every `files` entry that copies from the host.
func (m *Manifest) validateFileSources(manifestDir string) error {
	for _, path := range sortedFileKeys(m.Files) {
		spec := m.Files[path]
		if spec.From == "" {
			continue
		}
		src, err := resolveHostPath(spec.From, manifestDir)
		if err != nil {
			return err
		}
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("files: %q: %s does not exist", path, src)
		}
	}
	return nil
}

func (m *Manifest) validateMountsAndDevices(manifestDir string) error {
	for _, spec := range m.Mounts {
		host, _, err := splitMount(spec)
		if err != nil {
			return err
		}
		abs, err := resolveHostPath(host, manifestDir)
		if err != nil {
			return err
		}
		if _, err := os.Stat(abs); err != nil {
			// Podman would silently create a root-owned directory instead.
			return fmt.Errorf("mount %q: host path %s does not exist", spec, abs)
		}
	}
	for _, d := range m.Devices {
		if _, err := os.Stat(d); err != nil {
			return fmt.Errorf("device %s is not present on this host", d)
		}
	}
	return nil
}

// runtimeArgs renders the manifest's runtime surface as podman create flags.
func (m *Manifest) runtimeArgs(manifestDir string) ([]string, error) {
	var a []string
	// Sorted so the flags podman receives are stable between runs; an unstable
	// argument list makes a diff of two creates unreadable.
	for _, k := range sortedKeys(m.Env) {
		a = append(a, "-e", k+"="+m.Env[k])
	}
	for _, spec := range m.Mounts {
		host, rest, err := splitMount(spec)
		if err != nil {
			return nil, err
		}
		abs, err := resolveHostPath(host, manifestDir)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(abs); err != nil {
			// Podman would silently create a root-owned directory instead.
			return nil, fmt.Errorf("mount %q: host path %s does not exist", spec, abs)
		}
		a = append(a, "-v", abs+":"+rest)
	}
	for _, p := range m.Ports {
		a = append(a, "-p", p)
	}
	for _, c := range m.Caps {
		a = append(a, "--cap-add", c)
	}
	for _, d := range m.Devices {
		if _, err := os.Stat(d); err != nil {
			return nil, fmt.Errorf("device %s is not present on this host", d)
		}
		a = append(a, "--device", d)
	}
	if m.Limits.CPUs != "" {
		a = append(a, "--cpus", m.Limits.CPUs)
	}
	if m.Limits.Memory != "" {
		a = append(a, "--memory", m.Limits.Memory)
	}
	if m.Limits.PIDs > 0 {
		a = append(a, "--pids-limit", fmt.Sprint(m.Limits.PIDs))
	}
	return a, nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
