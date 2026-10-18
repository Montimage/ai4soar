"""
CACAO 2.0 -> Shuffle conversion (core/playbook_generation/cacao_to_shuffle.py).

Run: python -m unittest tests/test_cacao_to_shuffle.py

One synthetic playbook exercises every CACAO construct the converter maps; node templates
come from data/shuffle_python_apps.json (Shuffle's api.yaml files), no Shuffle instance needed.
"""

import base64
import glob
import json
import logging
import os
import sys
import unittest
from unittest import mock

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)

from core.intelligent_orchestration.parameterizer import PlaybookParameterizer, fill_secrets  # noqa: E402
from core.playbook_generation.cacao_to_shuffle import convert, parse_condition   # noqa: E402

RUNNER = "linux--3a7f9c1e-5b2d-4c8a-9e6f-7d1b2c3e4f50"
HOST = "ssh--0b6f1a9e-1d2c-4e3f-8a5b-6c7d8e9f0a1b"
WINHOST = "ssh--1c7a2b8f-2e3d-4f40-9b6c-7d8e9f0a1b2c"
TICKETS = "http-api--2d8b3c9a-3f4e-4051-8c7d-8e9f0a1b2c3d"
FIREWALL = "http-api--3e9c4dab-4a5f-4162-9d8e-9f0a1b2c3d4e"
AUTH_SSH = "user-auth--4fad5ebc-5b6a-4273-8e9f-0a1b2c3d4e5f"
AUTH_HTTP = "http-basic--5abe6fcd-6c7b-4384-9fa0-1b2c3d4e5f6a"
AUTH_OAUTH = "oauth2--6bcf7ade-7d8c-4495-8ab1-2c3d4e5f6a7b"


def sid(kind, n):
    return f"{kind}--00000000-0000-4000-8000-{n:012d}"


S = {name: sid(kind, i) for i, (name, kind) in enumerate([
    ("start", "start"), ("bash", "action"), ("if", "if-condition"), ("ssh", "action"),
    ("manual", "action"), ("switch", "switch-condition"), ("snort", "action"),
    ("other", "action"), ("par", "parallel"), ("ticket", "action"), ("openc2", "action"),
    ("ps_remote", "action"), ("ps_local", "action"), ("yara", "action"),
    ("while", "while-condition"), ("sub", "playbook-action"), ("end", "end")], start=1)}

OPENC2 = {"action": "deny", "target": {"ipv4_net": "198.51.100.7"}}
PS = 'Get-Process | Where-Object { $_.Name -eq "mimikatz" } | Stop-Process -Force'

PLAYBOOK = {
    "type": "playbook", "spec_version": "cacao-2.0", "id": "playbook--7cd08bef-8e9d-45a6-9bc2-3d4e5f6a7b8c",
    "name": "Coverage", "created_by": "identity--8de19cf0-9fae-46b7-8cd3-4e5f6a7b8c9d",
    "created": "2026-10-17T00:00:00Z", "modified": "2026-10-17T00:00:00Z",
    "playbook_variables": {"__severity__": {"type": "string", "external": True},
                           "__tool__": {"type": "string", "external": True}},
    "agent_definitions": {RUNNER: {"type": "linux", "name": "runner", "address": {"ipv4": ["127.0.0.1"]}}},
    "target_definitions": {
        HOST: {"type": "ssh", "name": "web-1", "address": {"ipv4": ["10.0.0.5"]}, "port": "2222",
               "authentication_info": AUTH_SSH},
        WINHOST: {"type": "ssh", "name": "win-1", "address": {"dname": ["win-1.corp"]},
                  "authentication_info": AUTH_SSH},
        TICKETS: {"type": "http-api", "name": "tickets", "address": {"url": ["https://tickets.example.org"]},
                  "authentication_info": AUTH_HTTP},
        FIREWALL: {"type": "http-api", "name": "fw", "address": {"dname": ["fw.example.org"]},
                   "authentication_info": AUTH_OAUTH},
    },
    "authentication_info_definitions": {
        AUTH_SSH: {"type": "user-auth", "username": "soar", "password": "s3cret"},
        AUTH_HTTP: {"type": "http-basic", "user_id": "api", "password": "pw"},
        AUTH_OAUTH: {"type": "oauth2", "token": "tok123"},
    },
    "workflow_start": S["start"],
    "workflow": {
        S["start"]: {"type": "start", "on_completion": S["bash"]},
        S["bash"]: {"type": "action", "name": "Collect", "agent": RUNNER,
                    "commands": [{"type": "bash", "command": "ps aux"},
                                 {"type": "bash", "command_b64": base64.b64encode(b"ss -tanp").decode()}],
                    "on_completion": S["if"]},
        S["if"]: {"type": "if-condition", "name": "High?", "condition": "[__severity__:value = 'high']",
                  "on_true": S["ssh"], "on_false": S["manual"]},
        S["ssh"]: {"type": "action", "name": "Isolate", "targets": [HOST],
                   "commands": [{"type": "ssh", "command": "iptables -I INPUT -j DROP"}], "on_completion": S["switch"]},
        S["manual"]: {"type": "action", "name": "Review",
                      "commands": [{"type": "manual", "command": "Confirm with the asset owner"}],
                      "on_completion": S["switch"]},
        S["switch"]: {"type": "switch-condition", "name": "Tool", "switch": "__tool__",
                      "cases": {"snort": S["snort"], "default": S["other"]}},
        S["snort"]: {"type": "action", "name": "Snort rule", "agent": RUNNER,
                     "commands": [{"type": "bash", "command": "echo snort"}], "on_completion": S["par"]},
        S["other"]: {"type": "action", "name": "Generic rule", "agent": RUNNER,
                     "commands": [{"type": "bash", "command": "echo other"}], "on_completion": S["par"]},
        S["par"]: {"type": "parallel", "name": "Notify", "next_steps": [S["ticket"], S["openc2"]]},
        S["ticket"]: {"type": "action", "name": "Ticket", "targets": [TICKETS],
                      "commands": [{"type": "http-api", "command": "POST /api/v1/incidents HTTP/1.1",
                                    "headers": {"Content-Type": ["application/json"]},
                                    "content": '{"title": "x"}'}], "on_completion": S["ps_remote"]},
        S["openc2"]: {"type": "action", "name": "Deny at firewall", "targets": [FIREWALL],
                      "commands": [{"type": "openc2-http", "command": "POST /openc2 HTTP/1.1",
                                    "content_b64": base64.b64encode(json.dumps(OPENC2).encode()).decode()}],
                      "on_completion": S["ps_remote"]},
        S["ps_remote"]: {"type": "action", "name": "Kill on Windows", "targets": [WINHOST],
                         "commands": [{"type": "powershell", "command": PS}], "on_completion": S["ps_local"]},
        S["ps_local"]: {"type": "action", "name": "PS nowhere", "agent": RUNNER,
                        "commands": [{"type": "powershell", "command": "Get-Date"}], "on_completion": S["yara"]},
        S["yara"]: {"type": "action", "name": "Scan", "agent": RUNNER,
                    "commands": [{"type": "yara", "command": "rule x {}"}], "on_completion": S["while"]},
        S["while"]: {"type": "while-condition", "name": "Retry", "condition": "[__severity__:value = 'x']",
                     "on_true": S["sub"]},
        S["sub"]: {"type": "playbook-action", "name": "Sub", "playbook_id": "playbook--9ef20d01-0abf-47c8-9de4-5f6a7b8c9d0e",
                   "on_completion": S["end"]},
        S["end"]: {"type": "end"},
    },
}


def node(wf, label_start):
    return next(a for a in wf["actions"] if a["label"].startswith(label_start))


def params(n):
    return {p["name"]: p["value"] for p in n["parameters"]}


def branch(wf, src_label, dst_label):
    src, dst = node(wf, src_label)["id"], node(wf, dst_label)["id"]
    return next(b for b in wf["branches"] if b["source_id"] == src and b["destination_id"] == dst)


class TestCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wf, cls.warnings = convert(PLAYBOOK)

    def test_bash_is_execute_bash_with_all_commands(self):
        n = node(self.wf, "Collect")
        self.assertEqual((n["app_name"], n["name"]), ("Shuffle Tools", "execute_bash"))
        self.assertEqual(params(n)["code"], "ps aux\nss -tanp")   # command_b64 decoded

    def test_ssh_command_runs_on_target(self):
        p = params(node(self.wf, "Isolate"))
        self.assertEqual(node(self.wf, "Isolate")["name"], "run_ssh_command")
        self.assertEqual((p["host"], p["port"], p["user_name"], p["password"]), ("10.0.0.5", "2222", "soar", "s3cret"))
        self.assertEqual(p["command"], "iptables -I INPUT -j DROP")

    def test_http_api_post_with_basic_auth(self):
        n = node(self.wf, "Ticket")
        p = params(n)
        self.assertEqual((n["app_name"], n["name"]), ("http", "POST"))
        self.assertEqual(p["url"], "https://tickets.example.org/api/v1/incidents")
        self.assertEqual((p["username"], p["password"]), ("api", "pw"))
        self.assertIn("Content-Type: application/json", p["headers"])
        self.assertEqual(p["body"], '{"title": "x"}')

    def test_openc2_post_with_oauth_and_decoded_body(self):
        p = params(node(self.wf, "Deny_at_firewall"))
        self.assertEqual(p["url"], "https://fw.example.org/openc2")
        self.assertIn("application/openc2-cmd+json", p["headers"])
        self.assertIn("Authorization: Bearer tok123", p["headers"])
        self.assertEqual(json.loads(p["body"]), OPENC2)

    def test_powershell_over_ssh_is_encoded(self):
        p = params(node(self.wf, "Kill_on_Windows"))
        self.assertEqual(p["host"], "win-1.corp")
        prefix = "powershell -NoProfile -NonInteractive -EncodedCommand "
        self.assertTrue(p["command"].startswith(prefix))
        self.assertEqual(base64.b64decode(p["command"][len(prefix):]).decode("utf-16-le"), PS)

    def test_echo_fallbacks_warn(self):
        for label, kind in (("PS_nowhere", "powershell"), ("Scan", "yara"), ("Review", "manual")):
            self.assertEqual(node(self.wf, label)["name"], "repeat_back_to_me")
            self.assertTrue(any(w.startswith(label.replace("_", " ")) for w in self.warnings), label)
        self.assertTrue(any("while-condition" in w for w in self.warnings))
        self.assertTrue(any("playbook-action" in w for w in self.warnings))

    def test_dry_run_runs_nothing(self):
        wf, _ = convert(PLAYBOOK, dry_run=True)
        runners = {a["name"] for a in wf["actions"]} & {"execute_bash", "run_ssh_command", "POST"}
        self.assertEqual(runners, set())


class TestControlFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wf, cls.warnings = convert(PLAYBOOK)

    def cond(self, b):
        return [(c["source"]["value"], c["condition"]["value"], c["destination"]["value"],
                 c["condition"]["configuration"]) for c in b["conditions"]]

    def test_if_true_and_negated_false(self):
        self.assertEqual(self.cond(branch(self.wf, "High", "Isolate")), [("$exec.severity", "equals", "high", False)])
        self.assertEqual(self.cond(branch(self.wf, "High", "Review")), [("$exec.severity", "equals", "high", True)])

    def test_switch_cases_and_default(self):
        self.assertEqual(self.cond(branch(self.wf, "Tool", "Snort_rule")), [("$exec.tool", "equals", "snort", False)])
        self.assertEqual(self.cond(branch(self.wf, "Tool", "Generic_rule")), [("$exec.tool", "does not equal", "snort", False)])

    def test_parallel_fans_out(self):
        self.assertEqual(branch(self.wf, "Notify", "Ticket")["conditions"], [])
        self.assertEqual(branch(self.wf, "Notify", "Deny_at_firewall")["conditions"], [])

    def test_start_node(self):
        self.assertEqual(self.wf["start"], node(self.wf, "Collect")["id"])

    def test_condition_shape_matches_shuffle(self):
        c = branch(self.wf, "High", "Isolate")["conditions"][0]
        self.assertEqual((c["source"]["name"], c["condition"]["name"], c["destination"]["name"]),
                         ("source", "condition", "destination"))
        self.assertEqual(c["source"]["variant"], "STATIC_VALUE")


class TestParseCondition(unittest.TestCase):
    CASES = {
        "[__s__:value = 'high']": [("__s__:value", "equals", "high", False)],
        "[__n__ >= 7]": [("__n__", "less than", "7", True)],
        "[__n__ <= 3]": [("__n__", "larger than", "3", True)],
        "[__h__ NOT LIKE 'web-%']": [("__h__", "startswith", "web-", True)],
        "[__m__ LIKE '%brute%']": [("__m__", "contains", "brute", False)],
        "[__m__ LIKE 'a_c']": [("__m__", "matches regex", "^a.c$", False)],
        "[__ip__ MATCHES '^10\\\\.']": [("__ip__", "matches regex", "^10\\.", False)],
        "[__t__ IN ('mmt', 'snort')]": [("__t__", "contains_any_of", "mmt,snort", False)],
        "__f__ == true": [("__f__", "equals", "true", False)],
        "[__a__ = '1' AND __b__ != 'x']": [("__a__", "equals", "1", False), ("__b__", "does not equal", "x", False)],
    }

    def test_supported(self):
        for expr, want in self.CASES.items():
            self.assertEqual(parse_condition(expr)[0], want, expr)

    def test_unsupported_with_reason(self):
        for expr in ("[__a__ = '1' OR __b__ = '2']", "[ipv4-addr:value = '1.2.3.4']", ""):
            parsed, why = parse_condition(expr)
            self.assertIsNone(parsed, expr)
            self.assertTrue(why, expr)


class TestLibraryAndShape(unittest.TestCase):
    def test_library_playbooks(self):
        P = PlaybookParameterizer()
        sample = {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.7", "disputed_ip": "192.0.2.20",
                  "hostname": "web-1", "username": "alice", "dst_port": 443, "duration_hours": 24}
        files = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "playbooks", "*.yaml")))
        self.assertEqual(len(files), 18)
        for f in files:
            with open(f) as fh:
                t = yaml.safe_load(fh)
            # The reputation playbook is automated end to end: a notification node, and the
            # firewall account comes from deployment settings (tested on its own below)
            automated = t["id"] == "pb-t1110-ip-reputation-block"
            pb = P.parameterize(t, {k: v for k, v in sample.items() if k in (t.get("parameters") or {})}).cacao
            wf, _ = convert(pb)
            names = {a["name"] for a in wf["actions"]}
            # every bash step acts on the victim over SSH; nothing runs in Shuffle's container
            self.assertIn("run_ssh_command", names, f)
            self.assertNotIn("execute_bash", names, f)
            if not automated:
                self.assertNotIn("repeat_back_to_me", names, f)
            for a in wf["actions"]:
                if a["name"] == "run_ssh_command":
                    p = params(a)
                    self.assertTrue(p["host"], (f, a["label"]))           # the victim
                    self.assertNotIn("ssh -o", p["command"], (f, a["label"]))
                    if not automated:
                        self.assertEqual(p.get("user_name", ""), "", f)    # left for the operator
            self.assertTrue(wf["start"] and wf["branches"], f)

    def test_reputation_playbook(self):
        env = {"VIRUSTOTAL_API_KEY": "vt-secret", "FIREWALL_SSH_HOST": "203.0.113.5",
               "FIREWALL_SSH_PORT": "2223", "FIREWALL_SSH_USER": "fw",
               "FIREWALL_SSH_PASSWORD": "fw-secret"}
        with open(os.path.join(os.path.dirname(__file__), "..", "playbooks",
                               "t1110_ip_reputation_block.yaml")) as fh:
            t = yaml.safe_load(fh)
        with mock.patch.dict(os.environ, env):
            pp = PlaybookParameterizer().parameterize(t, {"src_ip": "198.51.100.9"})
            self.assertNotIn("vt-secret", json.dumps(pp.cacao))       # never in the UI's CACAO
            self.assertNotIn("fw-secret", json.dumps(pp.cacao))
            self.assertEqual(pp.parameters_secret, ["virustotal_api_key", "firewall_password"])
            wf, _ = convert(fill_secrets(pp.cacao))
        by = {a["name"]: params(a) for a in wf["actions"]}
        vt = by["get_an_ip_address_report"]                         # the VirusTotal v3 app
        self.assertEqual((vt["apikey"], vt["ip"], vt["url"]),
                         ("vt-secret", "198.51.100.9", "https://www.virustotal.com"))
        ssh = by["run_ssh_command"]
        self.assertEqual((ssh["host"], ssh["port"], ssh["user_name"], ssh["password"]),
                         ("203.0.113.5", "2223", "fw", "fw-secret"))
        self.assertEqual(ssh["command"], "sudo iptables -I INPUT -s 198.51.100.9 -j DROP")
        # The decision node forks: notify (then block) when VirusTotal flags the IP, the
        # "no action" node otherwise (same comparison, negated)
        label = {a["id"]: a["label"] for a in wf["actions"]}
        forks = {label[b["destination_id"]]: b["conditions"] for b in wf["branches"] if b["conditions"]}
        self.assertEqual(set(forks), {"Notify_the_SOC", "Not_malicious_no_action"})
        for dest, negated in (("Notify_the_SOC", False), ("Not_malicious_no_action", True)):
            (c,) = forks[dest]
            self.assertTrue(c["source"]["value"].endswith(
                ".body.data.attributes.last_analysis_stats.malicious"))
            self.assertEqual((c["condition"]["value"], c["destination"]["value"],
                              c["condition"]["configuration"]), ("larger than", "0", negated))

    def test_nodes_have_editor_fields(self):
        wf, _ = convert(PLAYBOOK)
        for a in wf["actions"]:
            for k in ("category_label", "suggestion", "example", "app_version", "environment"):
                self.assertIn(k, a, (a["label"], k))
            for p in a["parameters"]:
                self.assertIn("custom_value", p, (a["label"], p["name"]))


if __name__ == "__main__":
    unittest.main()
