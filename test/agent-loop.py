#!/usr/bin/env python3
"""Drive spawn's MCP server the way an agent would: handshake, create a sandbox,
run a task in it, inspect what changed, check what it tried to reach, destroy it.

This is M4's exit criterion end to end -- "an agent completes a task in a sandbox
unattended, and spawn diff shows every file it changed" -- with no human in the loop.
"""
import json
import subprocess
import sys

ENV = "agentsim"


class MCP:
    def __init__(self):
        self.p = subprocess.Popen(
            ["spawn", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise SystemExit("the server closed the stream")
        return json.loads(line)

    def tool(self, tool_name, **args):
        r = self.call("tools/call", {"name": tool_name, "arguments": args})
        res = r.get("result") or {}
        text = (res.get("content") or [{}])[0].get("text", "")
        return text, bool(res.get("isError")), r.get("error")


fails = []


def check(label, cond, detail=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + label + ("  " + detail if detail and not cond else ""))
    if not cond:
        fails.append(label)


m = MCP()
init = m.call("initialize", {})["result"]
check("handshake", init["serverInfo"]["name"] == "spawn", str(init))

m.tool("spawn_destroy", name=ENV)  # in case an earlier run left it behind

print("\n-- the agent provisions a sandbox for a task it does not trust")
text, err, _ = m.tool("spawn_create", name=ENV, tools=["python3", "socat", "nftables", "iproute2", "gnugrep"])
check("spawn_create", not err, text)
check("deny-by-default is stated to the agent", "no network access" in text, text)

print("\n-- it runs the task")
text, err, _ = m.tool("spawn_exec", name=ENV,
                      command="python3 -c \"open('/root/result.json','w').write('{\\\"ok\\\": true}')\" && echo done")
check("spawn_exec runs the task", not err and "done" in text, text)

text, _, _ = m.tool("spawn_exec", name=ENV, command="cat /root/result.json")
check("the work is readable afterwards", '"ok": true' in text, text)

print("\n-- the task also does something it should not")
m.tool("spawn_exec", name=ENV, command="echo oops > /root/stray.txt; rm -f /etc/group")
m.tool("spawn_exec", name=ENV, command="timeout 4 socat -T2 - TCP:8.8.8.8:443 </dev/null 2>/dev/null; true")

print("\n-- the agent inspects what actually happened")
text, err, _ = m.tool("spawn_diff", name=ENV)
check("spawn_diff reports the intended file", "/root/result.json" in text, text)
check("spawn_diff reports the stray file", "/root/stray.txt" in text, text)
check("spawn_diff reports the deletion", "deleted" in text, text)

text, err, _ = m.tool("spawn_audit", name=ENV)
check("spawn_audit shows the blocked attempt", "8.8.8.8" in text, text)

print("\n-- snapshot, break, restore")
text, err, _ = m.tool("spawn_snapshot", name=ENV, tag="good")
check("spawn_snapshot", not err, text)
m.tool("spawn_exec", name=ENV, command="rm -f /root/result.json")
text, err, _ = m.tool("spawn_restore", name=ENV, tag="good")
check("spawn_restore", not err, text)
text, _, _ = m.tool("spawn_exec", name=ENV, command="cat /root/result.json")
check("restore brought the work back", '"ok": true' in text, text)

print("\n-- errors are reported as results the agent can read, not protocol faults")
text, err, rpcerr = m.tool("spawn_exec", name="nosuchenv", command="true")
check("a missing env is an isError result", err and rpcerr is None, f"{text!r} {rpcerr!r}")
text, err, _ = m.tool("spawn_exec", name=ENV, command="exit 7")
check("a failing command is not a server error", not err, text)

print("\n-- and it cleans up after itself")
text, err, _ = m.tool("spawn_list")
check("spawn_list shows the env", ENV in text, text.splitlines()[0] if text else "")
text, err, _ = m.tool("spawn_destroy", name=ENV)
check("spawn_destroy", not err, text)
text, _, _ = m.tool("spawn_list")
check("the env is gone", ENV not in text, text)

print()
print("FAILED: " + ", ".join(fails) if fails else "all agent-loop assertions passed")
sys.exit(1 if fails else 0)
