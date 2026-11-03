#!/usr/bin/env python3
"""Detection-only local triage for CVE-2026-58115, missing
authentication on the Node-RED HTTP interface in Siemens SIMATIC
IoT2050 Advanced gateways running Industrial OS with Node-RED
installed (CVSS 3.1 and 4.0: 10.0, Siemens advisory SSA-834709,
published 2026-08-11; CISA ICSA-26-237-03).

The flaw: affected devices do not enforce authentication on the
Node-RED HTTP interface, so an unauthenticated remote attacker
can create malicious flows through it and execute arbitrary code
on the underlying server with maximum privileges. In Node-RED
terms, that is one HTTP request: an inject node wired to an exec
node fires as soon as the flow is deployed, and the exec node
runs shell commands. VulnCheck caught exactly that in the wild
on 2026-10-30, saw the same source hit the flaw 16 times between
2026-10-30 and 2026-11-01, and reported it on 2026-11-02; the
observed flows dropped a Linux bot binary and, in other attempts,
installed persistent webshells.

This tool never touches the network, never probes a server,
never deploys a flow and never sends a payload. It grades only
things on a host you own or are authorised to audit:

1. A Siemens Industrial OS version you supply
   (--industrial-os 4.3.4.0): below V4.3.4.1 is VULNERABLE,
   V4.3.4.1 or later is FIXED. That range comes straight from
   SSA-834709 and covers only SIMATIC IoT2050 Advanced
   (6ES7647-0BA00-1YA2) with Node-RED installed.
2. A Node-RED settings file you supply (--settings settings.js):
   adminAuth present and uncommented means the editor asks for
   credentials, which closes the hole for a standalone install;
   adminAuth absent, or present only inside a comment, means the
   editor is open to anyone who can reach it, which grades
   VULNERABLE. An editor explicitly disabled with
   disableEditor: true grades FIXED on this check, because there
   is no editor to reach. This is a configuration grade, not a
   version grade, and the README says why that distinction
   matters: there is no Node-RED version that fixes this, only
   an authentication setting (standalone) or the Industrial OS
   update (IoT2050).
3. A flows file you supply (--flows flows.json): an offline
   audit for compromise indicators, not a verdict of compromise.
   An exec node, an http-in node wired to an exec node, or the
   observed dropper markers (/dev/shm drop, bot-linux-amd64,
   a download-and-execute chain) grades REVIEW, meaning a human
   must look at that flow, because legitimate flows use exec
   nodes too. A file with none of those markers grades CLEAN on
   this check only: it says nothing about flows that were
   deployed and deleted, or about anything outside the file.

--local looks for a settings file in the usual Node-RED user
directories on this host and grades what it finds, or reports
NOT FOUND. An offline inventory (--inventory-json) grades a
list of {name, industrial_os} entries for a fleet of IoT2050
gateways.

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable or
review finding, 1 = scan error. UNKNOWN and CLEAN-on-one-check
do not change the exit code, but neither is a clean bill of
health for the whole host: check the other signals too.
"""

import argparse
import json
import os
import re
import sys

VULNERABLE = "VULNERABLE"
FIXED = "FIXED"
UNKNOWN = "UNKNOWN"
REVIEW = "REVIEW"
CLEAN = "CLEAN"

FIXED_IOS = (4, 3, 4, 1)

# Markers seen in the observed exploitation, used only to flag a
# flows file for human review. They are indicators, not payloads,
# and this tool never fetches, decodes or runs anything they point to.
DROP_MARKERS = ("/dev/shm", "bot-linux-amd64", "bot-linux")


def parse_version(text):
    """Parse '4.3.4.1', 'V4.3.4.1', '4.3.4' into a 4-tuple, or None."""
    if not text:
        return None
    text = text.strip().lstrip("vV")
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", text)
    if not match:
        return None
    parts = [int(p) if p is not None else 0 for p in match.groups()]
    return tuple(parts)


def grade_industrial_os(version_text):
    """Grade a Siemens Industrial OS version against SSA-834709."""
    version = parse_version(version_text)
    if version is None:
        return {"check": "industrial_os", "input": version_text,
                "verdict": UNKNOWN,
                "detail": "Unparseable Industrial OS version; check the "
                          "version string against SSA-834709."}
    if version < FIXED_IOS:
        return {"check": "industrial_os", "input": version_text,
                "verdict": VULNERABLE,
                "detail": "Industrial OS below V4.3.4.1 with Node-RED "
                          "installed is affected by CVE-2026-58115; "
                          "update to V4.3.4.1 or later."}
    return {"check": "industrial_os", "input": version_text,
            "verdict": FIXED,
            "detail": "Industrial OS V4.3.4.1 or later: the Siemens "
                      "fix for CVE-2026-58115."}


def strip_js_comments(text):
    """Remove // and /* */ comments, so a commented-out adminAuth
    is not mistaken for a live one. String literals are not
    parsed; settings files rarely put '//' inside a string on the
    adminAuth lines, and the tests pin the common cases."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        lines.append(re.sub(r"(?<!:)//.*$", "", line))
    return "\n".join(lines)


def grade_settings_text(text):
    """Grade settings.js text for adminAuth / disableEditor."""
    code = strip_js_comments(text)
    if re.search(r"disableEditor\s*:\s*true", code):
        return {"check": "settings", "verdict": FIXED,
                "detail": "disableEditor is true: the editor is "
                          "disabled, so there is no unauthenticated "
                          "editor to reach through this flaw."}
    match = re.search(r"adminAuth\s*:\s*(\{[^}]*\}|[^,\n]+)", code)
    if match and match.group(1).strip() not in ("", "false", "null"):
        return {"check": "settings", "verdict": FIXED,
                "detail": "adminAuth is set and uncommented: the "
                          "editor requires credentials, which closes "
                          "CVE-2026-58115 for a standalone install."}
    return {"check": "settings", "verdict": VULNERABLE,
            "detail": "No live adminAuth found in settings.js: the "
                      "Node-RED editor accepts unauthenticated flow "
                      "changes, which is CVE-2026-58115. Set "
                      "adminAuth, or disable the editor."}


def grade_settings_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            result = grade_settings_text(handle.read())
    except OSError as exc:
        return {"check": "settings", "input": path, "verdict": UNKNOWN,
                "detail": "Could not read settings file: %s" % exc}
    result["input"] = path
    return result


def grade_flows_text(text):
    """Offline compromise-indicator audit of a flows JSON file."""
    try:
        nodes = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"check": "flows", "verdict": UNKNOWN,
                "detail": "Flows file is not valid JSON: %s" % exc}
    if isinstance(nodes, dict):
        nodes = nodes.get("flows", nodes.get("nodes", []))
    if not isinstance(nodes, list):
        return {"check": "flows", "verdict": UNKNOWN,
                "detail": "Flows file is not a JSON node list."}
    by_id = {n.get("id"): n for n in nodes if isinstance(n, dict)}
    reasons = []
    exec_ids = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("type") == "exec":
            exec_ids.add(node.get("id"))
            reasons.append("exec node '%s'" % (node.get("name") or node.get("id")))
    for node in nodes:
        if not isinstance(node, dict):
            continue
        wires = node.get("wires") or []
        flat = [w for group in wires for w in (group if isinstance(group, list) else [group])]
        if node.get("type") == "http in" and any(w in exec_ids for w in flat):
            reasons.append("http-in node wired to an exec node")
        blob = json.dumps(node)
        for marker in DROP_MARKERS:
            if marker in blob:
                reasons.append("dropper marker '%s' in a node" % marker)
                break
    if reasons:
        seen = []
        for reason in reasons:
            if reason not in seen:
                seen.append(reason)
        return {"check": "flows", "verdict": REVIEW,
                "detail": "Review these indicators by hand; exec nodes "
                          "are legitimate in some flows, so this is "
                          "not a compromise verdict: " + "; ".join(seen)}
    return {"check": "flows", "verdict": CLEAN,
            "detail": "No exec nodes, http-in-to-exec wiring or "
                      "observed dropper markers in this flows file."}


def grade_flows_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            result = grade_flows_text(handle.read())
    except OSError as exc:
        return {"check": "flows", "input": path, "verdict": UNKNOWN,
                "detail": "Could not read flows file: %s" % exc}
    result["input"] = path
    return result


def find_local_settings():
    candidates = [
        os.path.expanduser("~/.node-red/settings.js"),
        "/root/.node-red/settings.js",
        "/usr/local/lib/node_modules/node-red/settings.js",
        os.path.expanduser("~/node-red/settings.js"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def table():
    return ("CVE-2026-58115 (SSA-834709, CVSS 10.0)\n"
            "SIMATIC IoT2050 Advanced (6ES7647-0BA00-1YA2), "
            "Industrial OS with Node-RED installed:\n"
            "  affected: all versions < V4.3.4.1\n"
            "  fixed:    V4.3.4.1 or later\n"
            "Standalone Node-RED (any version):\n"
            "  vulnerable: settings.js with no live adminAuth\n"
            "  fixed:      adminAuth set, or disableEditor: true\n")


def render(results, as_json):
    if as_json:
        return json.dumps(results, indent=2)
    lines = []
    for result in results:
        lines.append("%s: %s -- %s" % (
            result.get("input") or result["check"],
            result["verdict"], result["detail"]))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only local triage for CVE-2026-58115.")
    parser.add_argument("--industrial-os", metavar="VERSION",
                        help="Siemens Industrial OS version to grade")
    parser.add_argument("--settings", metavar="PATH",
                        help="Node-RED settings.js file to grade")
    parser.add_argument("--flows", metavar="PATH",
                        help="Node-RED flows.json file to audit offline")
    parser.add_argument("--local", action="store_true",
                        help="Grade the settings.js found on this host")
    parser.add_argument("--inventory-json", metavar="PATH",
                        help="JSON list of {name, industrial_os} entries")
    parser.add_argument("--list", action="store_true",
                        help="Print the affected / fixed table")
    parser.add_argument("--json", action="store_true",
                        help="Machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print(table())
        return 0

    results = []
    if args.industrial_os:
        results.append(grade_industrial_os(args.industrial_os))
    if args.settings:
        results.append(grade_settings_file(args.settings))
    if args.flows:
        results.append(grade_flows_file(args.flows))
    if args.local:
        path = find_local_settings()
        if path is None:
            results.append({"check": "settings", "verdict": UNKNOWN,
                            "detail": "No Node-RED settings.js found in "
                                      "the usual user directories."})
        else:
            results.append(grade_settings_file(path))
    if args.inventory_json:
        try:
            with open(args.inventory_json, encoding="utf-8") as handle:
                entries = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print("Inventory error: %s" % exc, file=sys.stderr)
            return 1
        if not isinstance(entries, list):
            print("Inventory error: expected a JSON list", file=sys.stderr)
            return 1
        for entry in entries:
            result = grade_industrial_os(entry.get("industrial_os", ""))
            result["input"] = entry.get("name", entry.get("industrial_os", ""))
            results.append(result)

    if not results:
        parser.print_help()
        return 1
    print(render(results, args.json))
    if any(r["verdict"] in (VULNERABLE, REVIEW) for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
