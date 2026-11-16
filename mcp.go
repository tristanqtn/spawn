package main

// `spawn mcp` — an MCP server over stdio, so an agent can provision, use and destroy
// its own environment.
//
// It is a subcommand rather than a separate binary on purpose: it needs every bit of
// the manifest, policy and lifecycle code that already exists here, and a second
// module would mean a second release to keep in step for no benefit to anyone.
//
// The protocol is newline-delimited JSON-RPC 2.0 on stdin/stdout, which is what the
// MCP stdio transport is. That means NOTHING may be written to stdout except protocol
// messages -- a stray log line corrupts the stream -- so all diagnostics go to stderr.
//
// Agent envs are deny-by-default on egress. An agent that needs the network has to say
// which addresses, and every refusal lands in the audit log.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const mcpProtocolVersion = "2024-11-05"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// toolDef is one MCP tool. The descriptions matter as much as the code: they are the
// only thing telling an agent when reaching for a sandbox is the right move.
type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func strs(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func mcpTools() []toolDef {
	return []toolDef{
		{
			Name: "spawn_create",
			Description: "Create a disposable environment and build its tools. Use this before " +
				"running anything you would not want touching this machine: unfamiliar code, a " +
				"package you have not audited, a destructive command, or an experiment you want " +
				"to be able to throw away. Egress is DENIED by default; pass allow to permit " +
				"specific addresses. Many environments built from the same tool list share one " +
				"copy on disk, so creating another is cheap.",
			InputSchema: obj(map[string]any{
				"name":  str("short name for the environment, letters digits . _ + - only"),
				"tools": strs("nixpkgs package names, e.g. [\"python3\", \"curl\"]"),
				// Built from profileNames() rather than written out, because a hand-kept
				// list in a tool description is a list that goes stale silently -- and an
				// agent then asks for a suite that does not exist, or never learns about
				// one that does.
				"profiles": strs("built-in suites to include: " + strings.Join(profileNames(), ", ")),
				"allow":    strs("addresses or CIDRs the environment may reach, e.g. [\"1.1.1.1\"]. Omit for no network."),
			}, "name"),
		},
		{
			Name: "spawn_exec",
			Description: "Run a shell command inside an environment and return its output and " +
				"exit status. The environment keeps its filesystem between calls, so this is a " +
				"session rather than a one-shot.",
			InputSchema: obj(map[string]any{
				"name":    str("the environment's name"),
				"command": str("shell command to run inside it"),
			}, "name", "command"),
		},
		{
			Name: "spawn_diff",
			Description: "List every file the environment changed since it was created. Use this " +
				"to see exactly what a command or a script actually did, including what it " +
				"touched that it should not have.",
			InputSchema: obj(map[string]any{"name": str("the environment's name")}, "name"),
		},
		{
			Name: "spawn_audit",
			Description: "List the network destinations the environment's egress policy refused. " +
				"Use this to find out whether something tried to reach the network, and where.",
			InputSchema: obj(map[string]any{"name": str("the environment's name")}, "name"),
		},
		{
			Name: "spawn_snapshot",
			Description: "Copy the environment's filesystem aside under a tag, so a risky step " +
				"can be undone with spawn_restore.",
			InputSchema: obj(map[string]any{
				"name": str("the environment's name"),
				"tag":  str("a label for the snapshot; defaults to a timestamp"),
			}, "name"),
		},
		{
			Name:        "spawn_restore",
			Description: "Put a snapshot back, discarding everything the environment did since.",
			InputSchema: obj(map[string]any{
				"name": str("the environment's name"),
				"tag":  str("which snapshot to restore"),
			}, "name", "tag"),
		},
		{
			Name:        "spawn_list",
			Description: "List the environments that exist, with their state.",
			InputSchema: obj(map[string]any{}),
		},
		{
			Name: "spawn_destroy",
			Description: "Destroy an environment and its filesystem. Do this when finished: an " +
				"environment is meant to be disposable.",
			InputSchema: obj(map[string]any{"name": str("the environment's name")}, "name"),
		},
	}
}

// mcpServe reads requests until stdin closes.
func mcpServe(in io.Reader, out io.Writer) error {
	dec := bufio.NewScanner(in)
	// A single message can be large; a diff of a busy env is the usual reason.
	dec.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	enc := json.NewEncoder(out)

	for dec.Scan() {
		line := strings.TrimSpace(dec.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// -32700 is the JSON-RPC parse error code.
			enc.Encode(rpcResponse{JSONRPC: "2.0", ID: nil,
				Error: &rpcError{Code: -32700, Message: "invalid JSON: " + err.Error()}})
			continue
		}
		resp, send := handleRPC(req)
		if !send {
			// A notification has no id and takes no response.
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return dec.Err()
}

func handleRPC(req rpcRequest) (rpcResponse, bool) {
	r := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		r.Result = map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "spawn", "version": version},
		}
	case "notifications/initialized", "notifications/cancelled":
		return r, false
	case "tools/list":
		r.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			r.Error = &rpcError{Code: -32602, Message: "bad params: " + err.Error()}
			break
		}
		text, isErr := callTool(p.Name, p.Arguments)
		// A tool failure is reported as a RESULT with isError, not as a protocol
		// error: the agent needs to read the message and decide what to do, and a
		// protocol error would look like the server is broken.
		r.Result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isErr,
		}
	default:
		r.Error = &rpcError{Code: -32601, Message: "unknown method " + req.Method}
	}
	if req.ID == nil {
		return r, false
	}
	return r, true
}

type toolArgs struct {
	Name     string   `json:"name"`
	Command  string   `json:"command"`
	Tag      string   `json:"tag"`
	Tools    []string `json:"tools"`
	Profiles []string `json:"profiles"`
	Allow    []string `json:"allow"`
}

// agentManifest parses the rendered manifest for an agent-created env.
func agentManifest(a toolArgs) (*Manifest, error) {
	return Parse([]byte(agentManifestText(a)))
}

// agentManifestText renders the manifest for an agent-created env.
//
// Deny-by-default is the point: an agent sandbox that can reach the network is not a
// sandbox. The allow list is the only way out, and everything refused is audited.
func agentManifestText(a toolArgs) string {
	var b strings.Builder
	fmt.Fprintf(&b, "schema = 1\nname = %q\n", a.Name)
	if len(a.Profiles) > 0 {
		fmt.Fprintf(&b, "profiles = [")
		for i, p := range a.Profiles {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", p)
		}
		b.WriteString("]\n")
	}
	tools := a.Tools
	if len(tools) == 0 && len(a.Profiles) == 0 {
		// An env with nothing in it is almost never what was meant, and baseTools
		// alone gives a shell with no tools.
		tools = []string{"coreutils"}
	}
	if len(tools) > 0 {
		b.WriteString("tools = [")
		for i, t := range tools {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", t)
		}
		b.WriteString("]\n")
	}
	b.WriteString("\n[network]\negress = \"deny\"\n")
	if len(a.Allow) > 0 {
		b.WriteString("allow = [")
		for i, al := range a.Allow {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", al)
		}
		b.WriteString("]\n")
	}
	// nftables is needed for the policy to exist at all; networkPackages adds it.
	return b.String()
}

// mcpManifestPath is where spawn_create records an agent env's manifest, so the
// server can bring the env back without asking the agent to describe it again.
func mcpManifestPath(env string) string { return "/tmp/spawn-mcp-" + env + ".toml" }

// ensureUp restarts an env whose container is gone. restore deliberately removes the
// container before swapping the filesystem, so without this the next exec reported
// "no environment named ..." and the agent had no way to recover.
func ensureUp(env string) error {
	if inspect(env, "{{.Id}}") != "" {
		return nil
	}
	path := mcpManifestPath(env)
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no environment named %q; create it with spawn_create", env)
	}
	m, err := Parse(b)
	if err != nil {
		return err
	}
	return up(m, path, []string{"true"})
}

func callTool(name string, raw json.RawMessage) (string, bool) {
	var a toolArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return "bad arguments: " + err.Error(), true
		}
	}
	switch name {
	case "spawn_create":
		m, err := agentManifest(a)
		if err != nil {
			return err.Error(), true
		}
		path := mcpManifestPath(m.Name)
		// Write the manifest out, not just name it: ensureUp reads this back to
		// restart the env after a restore, and the container records the path.
		if err := os.WriteFile(path, []byte(agentManifestText(a)), 0o600); err != nil {
			return "could not record the manifest: " + err.Error(), true
		}
		if err := up(m, path, []string{"true"}); err != nil {
			return "could not create the environment: " + err.Error(), true
		}
		egress := "no network access"
		if len(a.Allow) > 0 {
			egress = "network limited to: " + strings.Join(a.Allow, ", ")
		}
		return fmt.Sprintf("environment %q is ready with %d packages; %s. "+
			"Refused destinations are recorded, see spawn_audit.", m.Name, len(m.resolved), egress), false

	case "spawn_exec":
		if a.Name == "" || a.Command == "" {
			return "name and command are both required", true
		}
		if err := ensureUp(a.Name); err != nil {
			return err.Error(), true
		}
		prof := inspect(a.Name, `{{index .Config.Labels "spawn.profile"}}`)
		if prof == "" {
			return fmt.Sprintf("no environment named %q; create it with spawn_create", a.Name), true
		}
		out, err := podmanOut("exec", "-e", "PATH="+prof+"/bin", "-w", "/root",
			cname(a.Name), prof+"/bin/bash", "-lc", a.Command)
		if err != nil {
			// The command's own failure is information, not a server error.
			return fmt.Sprintf("command failed: %v\n%s", err, out), false
		}
		if out == "" {
			return "(no output; exit status 0)", false
		}
		return out, false

	case "spawn_diff":
		ch, err := diffEnv(a.Name)
		if err != nil {
			return err.Error(), true
		}
		if len(ch) == 0 {
			return "nothing changed since the environment was created", false
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d file(s) changed:\n", len(ch))
		for _, c := range ch {
			fmt.Fprintf(&b, "  %-9s %8d  %s\n", c.Kind, c.Size, c.Path)
		}
		return b.String(), false

	case "spawn_audit":
		prof := inspect(a.Name, `{{index .Config.Labels "spawn.profile"}}`)
		if prof == "" {
			return fmt.Sprintf("no environment named %q", a.Name), true
		}
		entries, err := auditEgress(a.Name, prof)
		if err != nil {
			return err.Error(), true
		}
		if len(entries) == 0 {
			return "the environment has not tried to reach any blocked address", false
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d destination(s) refused by the egress policy:\n", len(entries))
		for _, e := range entries {
			fmt.Fprintf(&b, "  %s\n", e.Addr)
		}
		return b.String(), false

	case "spawn_snapshot":
		dst, err := snapshot(a.Name, a.Tag)
		if err != nil {
			return err.Error(), true
		}
		return "snapshot saved: " + dst, false

	case "spawn_restore":
		if err := restore(a.Name, a.Tag); err != nil {
			return err.Error(), true
		}
		// Bring it straight back: leaving the agent with a restored filesystem and
		// no container is a trap it cannot see.
		if err := ensureUp(a.Name); err != nil {
			return "restored, but the environment could not be restarted: " + err.Error(), true
		}
		return fmt.Sprintf("restored %q from %q and restarted it", a.Name, a.Tag), false

	case "spawn_list":
		out, err := podmanOut("ps", "-a", "--filter", "label=spawn.name", "--format",
			`{{index .Labels "spawn.name"}} {{.State}}`)
		if err != nil {
			return err.Error(), true
		}
		if out == "" {
			return "no environments exist", false
		}
		return out, false

	case "spawn_destroy":
		if err := rm(a.Name, true); err != nil {
			return err.Error(), true
		}
		return fmt.Sprintf("environment %q and its filesystem are gone", a.Name), false
	}
	return "unknown tool " + name, true
}

// mcpMain is the subcommand entry point.
func mcpMain() {
	if err := requireDeps(depNix, depPodman); err != nil {
		// stderr, never stdout: stdout carries the protocol.
		fmt.Fprintln(os.Stderr, "spawn:", err)
		os.Exit(1)
	}
	// Everything else in spawn prints progress with fmt.Printf, which writes to
	// os.Stdout at call time -- and on this transport stdout carries the protocol, so
	// one "removed env ..." line corrupts the stream and the agent sees malformed
	// JSON. Point os.Stdout at stderr and keep the real handle for protocol only.
	protocol := os.Stdout
	os.Stdout = os.Stderr
	if err := mcpServe(os.Stdin, protocol); err != nil {
		fmt.Fprintln(os.Stderr, "spawn mcp:", err)
		os.Exit(1)
	}
}
