# `node-red-scanner`

Local triage for `CVE-2026-58115`, the `10.0` missing-authentication flaw in `Node-RED` on `Siemens SIMATIC IoT2050 Advanced` gateways. Give it an `Industrial OS` version you own, or a `settings.js` file you own, and it tells you whether that install is still open. It never touches the network, never probes a server, never deploys a flow, never sends a payload.

## `The flaw`

`Node-RED` is a flow-based editor built on `Node.js`, and it is wired into industrial kit: `Siemens` embeds it in the `SIMATIC IoT2050 Advanced` gateway. On affected gateways the `Node-RED HTTP` interface does not enforce authentication, so an unauthenticated remote attacker can create malicious flows and execute arbitrary code on the underlying server with maximum privileges.

In `Node-RED` terms that is one request. An `inject` node wired to an `exec` node fires as soon as the flow is deployed, and the `exec` node runs shell commands. `VulnCheck` caught exactly that in the wild on `30 October 2026`: a single `POST /flows` deploying an auto-triggering flow that pulled a `Linux` bot binary, plus later attempts that installed persistent webshells instead. Between `30 October` and `1 November` the same source hit this flaw `16` times. The tool does not reproduce any of that. Its job is to tell you, before an attacker does, whether your install is open.

## `What it checks`

- `An Industrial OS version you supply` (`--industrial-os 4.3.4.0`): graded against the `Siemens` fixed build, for `IoT2050 Advanced` gateways only
- `A settings file you supply` (`--settings settings.js`): graded for a live, uncommented `adminAuth`, for any standalone `Node-RED` install
- `This host` (`--local`): the `settings.js` in the usual `Node-RED` user directories, or `NOT FOUND`
- `A flows file you supply` (`--flows flows.json`): an offline audit for compromise indicators, graded `REVIEW`, never a compromise verdict on its own
- `An offline inventory` (`--inventory-json inventory.json`): a `JSON` list of `{name, industrial_os}` entries, for a fleet of gateways
- `The full table` (`--list`): the affected range and the fixed build

## `The trap: this is a configuration flaw, not a version flaw`

| `Signal` | `Affected` | `Fixed` |
| --- | --- | --- |
| `SIMATIC IoT2050 Advanced` (`6ES7647-0BA00-1YA2`), `Industrial OS` with `Node-RED` installed | below `V4.3.4.1` | `V4.3.4.1` or later |
| Standalone `Node-RED`, any version | `settings.js` with no live `adminAuth` | `adminAuth` set, or `disableEditor: true` |

Do not grade a `Node-RED` version number against this `CVE`. There is no `Node-RED` release that fixes it, because the flaw is missing authentication, not a bug in a particular release. Upgrading `Node-RED` while leaving `adminAuth` unset leaves the editor exactly as open as before. On an `IoT2050`, the fix is the `Industrial OS` update to `V4.3.4.1` or later, which enforces authentication on the web interface. On a standalone install, the fix is setting `adminAuth` in `settings.js` yourself.

Two more things to not get wrong. First, a commented-out `adminAuth` is not authentication. The tool strips `//` and `/* */` comments before grading, so a settings file that only mentions `adminAuth` in a comment still grades `VULNERABLE`. Second, an `exec` node in a flows file is not proof of compromise. Plenty of legitimate flows use `exec` nodes, so the flows check grades `REVIEW` and tells a human what to look at: `exec` nodes, `http-in` nodes wired to `exec` nodes, and the observed dropper markers (`/dev/shm` drops, `bot-linux-amd64`). A `CLEAN` flows grade means none of those markers are in that file, nothing more. It says nothing about flows that were deployed and deleted.

## `Usage`

```sh
# vulnerable gateway
python3 node_red_scanner.py --industrial-os 4.3.4.0

# fixed gateway
python3 node_red_scanner.py --industrial-os 4.3.4.1

# standalone install, open editor
python3 node_red_scanner.py --settings ~/.node-red/settings.js

# offline compromise-indicator audit of a flows file you own
python3 node_red_scanner.py --flows flows.json

# on the host itself
python3 node_red_scanner.py --local

# machine-readable output for fleets
python3 node_red_scanner.py --industrial-os 4.3.4.0 --json

# the full fixed-version table
python3 node_red_scanner.py --list
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable or review finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean.

## `Where sources disagree, and what is still unverified`

First, the timeline. `Siemens` published advisory `SSA-834709` on `11 August 2026`, and `CISA` advisory `ICSA-26-237-03` followed the same month. At that point `CISA` reported no confirmed in-the-wild exploitation. That changed at the end of `October`: `VulnCheck` caught exploitation on `30 October`, reported it on `2 November`, and `The Register` covered it the same day. This tool follows the `November` exploitation evidence, not the `August` position, and it says so plainly: this is a newly exploited flaw, not a newly disclosed one. The trend trigger here is the `2 November` exploitation report, inside the last `72` hours.

Second, `KEV` status. As of this build, the flaw sits in `VulnCheck`'s `KEV` catalogue, not in `CISA`'s `KEV`, per both `VulnCheck` and `The Register`. Do not cite it as a `CISA KEV` entry until `CISA` lists it.

Third, scope. The `Siemens` advisory covers only `SIMATIC IoT2050 Advanced` (`6ES7647-0BA00-1YA2`) running `Industrial OS` with `Node-RED` installed. The underlying condition, an unauthenticated `Node-RED` editor, applies to any `Node-RED` install without `adminAuth`, and the settings check grades that separately, labelled as a standalone grade, not as a `Siemens` range claim. `VulnCheck` notes `Emerson` documentation also highlights `Node-RED` use but has not validated whether its products are impacted; this tool makes no claim about `Emerson` kit.

Fourth, no widely available local triage scanner for this flaw was found when this build was checked. What exists is log detection: `Sigma` / `Splunk` / `KQL` rules for the `POST /flows` deploy pattern, and `VulnCheck`'s own detection. Those watch traffic after the fact. This tool is the other side of that: an offline check of the version and the configuration before anything is deployed. If a standalone scanner already covers this well, open an `issue` and say so.

## `Mitigation if you cannot patch today`

Update is the fix; there is no configuration workaround on the gateway beyond the update itself, per `Siemens`. Until you can update, do what the advisory says: uninstall `Node-RED` if you do not need it, harden the install per the `Node-RED` user guide, and never leave the admin interface, port `1880` included, reachable from the public internet. Put it behind a firewall, a `VPN`, or a reverse proxy with multi-factor authentication. For a standalone install, setting `adminAuth` today closes the hole this `CVE` describes, and reviewing deployed flows for unauthorised `exec` nodes or undocumented `http` endpoints is the compromise check to run alongside it.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`19` tests: `Industrial OS` versions below and above the fixed build, unparseable versions as `UNKNOWN`, `adminAuth` present, absent and commented-out, `disableEditor`, clean flows, `exec` nodes, `http-in` wired to `exec`, dropper markers, invalid flows `JSON`, `CLI` exit codes, `JSON` output, the full table, and the inventory file.

## `Thanks to`

- `Siemens ProductCERT`, for advisory `SSA-834709` and the fixed `Industrial OS` build this tool grades against
- `VulnCheck`, for catching the in-the-wild exploitation and publishing the analysis this build is timed on
- `CISA`, for advisory `ICSA-26-237-03` and the affected-product scope
- The `Node-RED` project, for the `adminAuth` and `disableEditor` settings this tool grades

## `Disclaimer`

Defensive triage only. This tool checks version strings, settings files and flows files you supply, on systems you own or are authorised to audit. It sends no traffic, probes no server, deploys no flow, and is not a substitute for the vendor advisory.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
