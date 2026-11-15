package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// roundtrip feeds one request through the server and returns the decoded response.
func roundtrip(t *testing.T, line string) map[string]any {
	t.Helper()
	var out strings.Builder
	if err := mcpServe(strings.NewReader(line+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSpace(out.String())
	if s == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("server emitted non-JSON %q: %v", s, err)
	}
	return m
}

func TestMCPHandshake(t *testing.T) {
	r := roundtrip(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", r)
	}
	if res["protocolVersion"] != mcpProtocolVersion {
		t.Errorf("protocolVersion = %v", res["protocolVersion"])
	}
	// Without declaring the tools capability a client will not ask for any tools.
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("the server does not advertise tools: %v", caps)
	}
}

// A notification has no id and must draw no response. Answering one corrupts the
// stream, because the client is not expecting a message there.
func TestMCPNotificationsAreSilent(t *testing.T) {
	for _, n := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`,
	} {
		if got := roundtrip(t, n); got != nil {
			t.Errorf("%s drew a response: %v", n, got)
		}
	}
}

func TestMCPToolsListIsWellFormed(t *testing.T) {
	r := roundtrip(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	res := r["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) < 8 {
		t.Fatalf("expected the full tool set, got %d", len(tools))
	}
	for _, raw := range tools {
		tl := raw.(map[string]any)
		name, _ := tl["name"].(string)
		desc, _ := tl["description"].(string)
		if !strings.HasPrefix(name, "spawn_") {
			t.Errorf("tool %q is not namespaced", name)
		}
		// The description is the only thing telling an agent when to use the tool,
		// so an empty or terse one is a bug, not a style question.
		if len(desc) < 40 {
			t.Errorf("tool %q has a description too short to guide an agent: %q", name, desc)
		}
		if _, ok := tl["inputSchema"].(map[string]any); !ok {
			t.Errorf("tool %q has no input schema", name)
		}
	}
}

func TestMCPUnknownMethodAndBadJSON(t *testing.T) {
	r := roundtrip(t, `{"jsonrpc":"2.0","id":3,"method":"nope/nope"}`)
	if r["error"] == nil {
		t.Error("an unknown method should be a protocol error")
	}
	r = roundtrip(t, `{not json`)
	e, _ := r["error"].(map[string]any)
	if e == nil || e["code"].(float64) != -32700 {
		t.Errorf("malformed JSON should give the parse error code: %v", r)
	}
}

// A tool failure is a RESULT with isError, never a JSON-RPC error: the agent has to
// read the message and decide, and a protocol error looks like a broken server.
func TestMCPToolFailureIsAResult(t *testing.T) {
	r := roundtrip(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call",`+
		`"params":{"name":"spawn_diff","arguments":{"name":"definitelynotanenv"}}}`)
	if r["error"] != nil {
		t.Errorf("a tool failure became a protocol error: %v", r["error"])
	}
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", r)
	}
	if res["isError"] != true {
		t.Errorf("the failure was not flagged: %v", res)
	}
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "baseline") {
		t.Errorf("the message does not say what went wrong: %v", content["text"])
	}
}

func TestMCPUnknownToolIsRejected(t *testing.T) {
	r := roundtrip(t, `{"jsonrpc":"2.0","id":5,"method":"tools/call",`+
		`"params":{"name":"spawn_rm_minus_rf","arguments":{}}}`)
	res := r["result"].(map[string]any)
	if res["isError"] != true {
		t.Errorf("an unknown tool should be an error result: %v", res)
	}
}

// Deny-by-default is the whole premise of an agent sandbox, so it is asserted on the
// generated manifest rather than trusted to the code path that writes it.
func TestAgentManifestDeniesEgressByDefault(t *testing.T) {
	m, err := agentManifest(toolArgs{Name: "a", Tools: []string{"python3"}})
	if err != nil {
		t.Fatal(err)
	}
	if m.effectiveEgress() != egressDeny {
		t.Fatalf("an agent env defaults to %q, not deny", m.effectiveEgress())
	}
	rs := m.nftRuleset(nil)
	if !strings.Contains(rs, "policy drop;") {
		t.Error("the generated policy does not default-drop")
	}
	// nftables has to be present or the policy silently does nothing.
	if !m.has("nftables") {
		t.Error("an agent env has no nftables, so its policy would never be applied")
	}
	// And the audit set, or a refusal leaves no trace.
	if !strings.Contains(rs, "update @blocked") {
		t.Error("the policy does not record refused destinations")
	}

	// An explicit allow list is the only way out, and nothing else widens.
	withAllow, err := agentManifest(toolArgs{Name: "a", Tools: []string{"curl"}, Allow: []string{"1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	rs = withAllow.nftRuleset(nil)
	if !strings.Contains(rs, "ip daddr 1.1.1.1 accept") {
		t.Error("the allow list was dropped")
	}
	if strings.Contains(rs, "0.0.0.0/0") {
		t.Error("the policy opened everything")
	}

	// An env with no tools at all would be a shell with nothing in it.
	bare, err := agentManifest(toolArgs{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bare.resolved) < 2 {
		t.Error("an env created with no tools should still be usable")
	}
}

// The manifest has to be written out, not merely named: ensureUp reads it back to
// restart an env after a restore, and without it a restore left the agent stuck.
func TestAgentManifestTextParsesBack(t *testing.T) {
	a := toolArgs{Name: "rt", Tools: []string{"python3"}, Profiles: []string{"general"}, Allow: []string{"1.1.1.1"}}
	text := agentManifestText(a)
	m, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("the manifest spawn writes for an agent does not parse: %v\n%s", err, text)
	}
	if m.Name != "rt" || !m.has("python3") || m.effectiveEgress() != egressDeny {
		t.Errorf("round-trip lost something: %+v", m)
	}
}
