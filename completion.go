package main

// Shell completion. The scripts below are deliberately thin: each one collects the
// words typed so far and asks `spawn __complete` what comes next, so the candidate
// logic lives in Go and is shared by every shell rather than reimplemented three
// times in three dialects.
//
// This is why spawn has no CLI framework. Completion is the usual reason to adopt
// one, and it costs about a hundred lines to do directly.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var commands = map[string]string{
	"init":       "write a manifest and editable dotfiles here (--engagement for a pentest one)",
	"up":         "build an env and enter it, by manifest or by name",
	"check":      "evaluate a manifest without building",
	"smoke":      "run every tool in a suite and report what works",
	"ls":         "list envs",
	"stop":       "stop an env, keeping its rootfs",
	"rm":         "destroy an env and its rootfs",
	"diff":       "show every file the env changed",
	"audit":      "show which destinations the egress policy refused",
	"mcp":        "serve MCP over stdio, so an agent can run its own envs",
	"snapshot":   "copy the env's filesystem aside",
	"snapshots":  "list an env's snapshots",
	"restore":    "put a snapshot back",
	"fork":       "copy an env into a new one",
	"export":     "write an env to a portable archive",
	"import":     "rebuild an env from an archive",
	"doctor":     "check this host, and a manifest against it",
	"profiles":   "list the built-in suites",
	"completion": "print a shell completion script",
	"version":    "print the version",
	"help":       "show this help",
}

// commandOrder is the order the help screen uses: roughly the order a new user meets
// them, not alphabetical.
var commandOrder = []string{"init", "up", "ls", "stop", "rm", "diff", "audit", "snapshot",
	"snapshots", "restore", "fork", "export", "import", "check", "smoke", "doctor", "mcp", "profiles", "completion",
	"version", "help"}

const bashCompletion = `# spawn bash completion.  Install with:
#   spawn completion bash > /etc/bash_completion.d/spawn
# or, for this shell only:
#   source <(spawn completion bash)
_spawn_complete() {
  local IFS=$'\n'
  COMPREPLY=($(compgen -W "$(spawn __complete "${COMP_WORDS[@]:1:COMP_CWORD-1}")" -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -o default -F _spawn_complete spawn
`

const zshCompletion = `#compdef spawn
# spawn zsh completion.  Install by putting this on your fpath as _spawn:
#   spawn completion zsh > "${fpath[1]}/_spawn"
_spawn() {
  local -a candidates
  candidates=(${(f)"$(spawn __complete --describe ${words[2,$((CURRENT-1))]})"})
  if (( ${#candidates} )); then
    _describe -t spawn 'spawn' candidates
  else
    _files
  fi
}
_spawn "$@"
`

const fishCompletion = `# spawn fish completion.  Install with:
#   spawn completion fish > ~/.config/fish/completions/spawn.fish
function __spawn_complete
  set -l tokens (commandline -opc)
  spawn __complete $tokens[2..-1]
end
complete -c spawn -f -a '(__spawn_complete)'
# Manifests are still offered wherever a path makes sense.
complete -c spawn -n '__fish_seen_subcommand_from up check doctor' -k -a '(__fish_complete_suffix .toml)'
`

func completionScript(shell string) (string, error) {
	switch shell {
	case "bash":
		return bashCompletion, nil
	case "zsh":
		return zshCompletion, nil
	case "fish":
		return fishCompletion, nil
	}
	return "", fmt.Errorf("unknown shell %q: want bash, zsh or fish", shell)
}

// complete prints one candidate per line for the words already typed.
//
// Descriptions are a zsh convention. bash's compgen -W splits on whitespace, so a
// "value:description" line there becomes one candidate per WORD of the description --
// which is what it did until this was tested in a real shell. Only zsh asks for them.
func complete(words []string) {
	describe := len(words) > 0 && words[0] == "--describe"
	if describe {
		words = words[1:]
	}
	for _, c := range candidates(words) {
		if describe {
			fmt.Println(c)
			continue
		}
		value, _, _ := strings.Cut(c, ":")
		fmt.Println(value)
	}
}

func candidates(words []string) []string {
	// Nothing typed yet, or still on the first word: offer the commands.
	if len(words) == 0 {
		return describedCommands()
	}
	switch words[0] {
	case "stop":
		// Only a running env can usefully be stopped.
		if len(words) > 1 {
			return nil
		}
		return envNames("running")
	case "diff", "audit", "snapshot", "snapshots", "fork", "export":
		if len(words) > 1 {
			return nil
		}
		return envNames("")
	case "restore":
		if len(words) == 1 {
			return envNames("")
		}
		if len(words) == 2 {
			snaps, _ := listSnapshots(words[1])
			return snaps
		}
		return nil
	case "rm":
		if len(words) == 1 {
			return append([]string{"--purge:also delete persisted data"}, envNames("")...)
		}
		if len(words) == 2 && words[1] == "--purge" {
			return envNames("")
		}
		return nil
	case "completion":
		if len(words) > 1 {
			return nil
		}
		return []string{"bash:bash completion script", "zsh:zsh completion script", "fish:fish completion script"}
	case "up":
		// `spawn up` takes a manifest or the name of an existing env, so offer both.
		// Past the first argument everything is a command for inside the env, which
		// the shell's default completion handles better than spawn could.
		if len(words) > 1 {
			return nil
		}
		return append(envNames(""), manifestsHere()...)
	case "check", "doctor":
		if len(words) > 1 {
			return nil
		}
		return manifestsHere()
	case "profiles":
		if len(words) > 1 {
			return nil
		}
		return []string{"--names:print just the suite names, one per line"}
	case "smoke":
		// A suite, not a manifest: smoke builds its own throwaway env.
		if len(words) > 2 {
			return nil
		}
		out := []string{"--keep:leave the env behind to poke at a failure"}
		for _, n := range profileNames() {
			d, _ := profileDescription(n)
			out = append(out, n+":"+d)
		}
		return out
	case "init":
		if len(words) > 1 {
			return nil
		}
		return []string{"--force:overwrite files that are already there",
			"--engagement:start from the pentest manifest instead of the plain one"}
	case "ls", "version", "help", "mcp":
		return nil
	}
	if len(words) == 1 {
		return describedCommands()
	}
	return nil
}

func describedCommands() []string {
	out := make([]string, 0, len(commandOrder))
	for _, c := range commandOrder {
		out = append(out, c+":"+commands[c])
	}
	return out
}

// envNames lists existing envs, optionally filtered by state, for stop and rm.
func envNames(state string) []string {
	args := []string{"ps", "-a", "--filter", "label=spawn.name", "--format", `{{index .Labels "spawn.name"}}`}
	if state != "" {
		args = append(args, "--filter", "status="+state)
	}
	out, err := podmanOut(args...)
	if err != nil || out == "" {
		return nil
	}
	names := strings.Split(out, "\n")
	sort.Strings(names)
	return names
}

func manifestsHere() []string {
	paths, err := filepath.Glob("*.toml")
	if err != nil {
		return nil
	}
	sort.Strings(paths)
	return paths
}

// usage prints the help screen: banner, commands as a table, then a worked example.
func printUsage() {
	banner(os.Stdout)
	fmt.Println(ui.paint(ui.bold, "USAGE"))
	fmt.Println("  spawn <command> [manifest.toml] [args...]")
	fmt.Println()
	fmt.Println(ui.paint(ui.bold, "COMMANDS"))
	t := newTable()
	for _, c := range commandOrder {
		t.add("  "+c, ui.paint(ui.dim, commands[c]))
	}
	t.print()
	fmt.Println()
	fmt.Println(ui.paint(ui.bold, "EXAMPLE"))
	fmt.Println(ui.paint(ui.dim, `  cat > spawn.toml <<'EOF'
  schema = 1
  name = "lab"
  profiles = ["general", "web"]
  EOF
  spawn init        # or start from a configured template
  spawn up          # build it and get a shell
  spawn up lab      # re-enter that env from anywhere
  spawn ls          # see it running
  spawn rm lab      # throw it away`))
	fmt.Println()
	fmt.Printf("A manifest defaults to %s in the current directory.\n", ui.paint(ui.cyan, "./spawn.toml"))
}
