# AETHER

## New: practical troubleshooting tools (18 November 2026)

Open **/troubleshoot** on the running app, or choose **Real capture & DNS tools** in the dashboard.

- Open an authorized classic PCAP capture locally in your browser. Find observed UDP DNS failure codes, TCP reset flags and largest directional connections. Read the evidence, possible meaning and next checks. This is evidence triage, not automatic root-cause proof.
- Download a redacted standalone HTML incident report or JSON. Exports omit IP addresses, queried names and filename; device aliases and ports remain. Review before sharing.
- Run a real **Google Public DNS-over-HTTPS** A-record check for a public domain. Inspect the actual JSON response, including DNS status and addresses. This tests Google's resolver, not your local resolver, website reachability or Wi-Fi quality.
- Keep the original simulation lab for hypothetical policy changes and fault recovery. Captures do not automatically construct its topology or configure real devices.

### Privacy and safe operation

Capture analysis sends no file or findings over the network, uses no AI, and stores no file in browser storage. Clear or close the tab to discard it. Only an explicit live DNS check sends the entered domain through AETHER to Google's fixed API endpoint. No arbitrary URL requests, router access, active scans or paid APIs. Resolver requests have a five-second timeout, 128 KB response cap, two concurrent slots, 12 upstream checks/minute globally and a 60-second cache. API endpoint: `GET /api/dns-check?name=example.com`.

Classic PCAP 2.4 only: both byte orders and microsecond/nanosecond timestamps; Ethernet (up to two VLAN tags), raw IPv4 and Linux cooked v1. Up to 20 MB and 100,000 records. No PCAPNG, IPv6 decoding, IP reassembly, TCP DNS reconstruction, TLS decryption or live capture. In Wireshark use File > Save As > classic pcap to convert PCAPNG. The built-in capture is visibly **synthetic**, not a real-world benchmark. Totals use capture original-byte metadata, not measured link capacity. Non-decoded traffic and shortened records are disclosed.

### Reproduce the checks

```sh
python -m unittest discover -s tests -v
node tests/capture.test.js
```

The upgrade's local run passed 42 Python tests (32 existing plus 10 DNS tests) and 19 JavaScript capture tests. A Chromium walkthrough separately checked sample/file input, malformed rejection, clearing, redacted HTML/JSON downloads, no capture-analysis network requests, real DNS success/NXDOMAIN/invalid input, mobile layout and baseline connectivity. Tests are not a guarantee of production correctness. Windows has not been tested.

### Sources and credit

Capture header interpretation adapted from **Ben Foxall's pcap-decoder**, MIT license, pinned source commit `d77edf1248d5828ebf4f9924645e4c738623a9c5`. Full license is in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No npm runtime dependencies or remote scripts are bundled.

- https://github.com/benfoxall/pcap-decoder
- https://wiki.wireshark.org/Development/LibpcapFileFormat/
- https://developers.google.com/speed/public-dns/docs/doh/json

The remainder of this README documents the original simulation lab, not real-network control.

---

### Intent-based network intelligence, with a safety gate before every change.

A standalone full-stack educational **network digital twin**. Express a network objective, inspect the structured policy and dry-run estimate, approve it, inject a link fault, inspect rerouting, and restore a snapshot.

**This is a real working web app with a simulated data plane.** It does not transmit packets, administer your network, run Mininet/Ryu, install OpenFlow, or claim measured physical-network results. It adapts the supplied MA3104 project proposal into an independently hosted demonstrator that needs no privileged local lab.

## Run independently

Python 3.10 or later. No runtime packages or paid APIs required.

```bash
python server.py
```

Open `http://127.0.0.1:8000`. On Windows, use `py server.py` if Python is installed under the `py` launcher. Windows execution has not been verified on a Windows machine. The tested environment is Linux/Python 3.10 with Chromium.

```bash
# Linux/macOS, optional port override
PORT=9000 python server.py
# PowerShell
$env:PORT=9000; py server.py
```

Docker is optional: `docker build -t aether .` then `docker run --rm -p 8000:8000 aether`. Docker is optional locally. The container image was built and deployed on Render with Python 3.12; all 32 unittest methods passed during that build.

## What works

- Responsive command center, animated SVG topology, flow explorer, policy registry, version history, decision trace and JSON evidence export.
- Six switches, eight hosts and eleven redundant switch links. Hosts h1/h2 attach to s3, h3/h4 to s4, h5/h6 to s5, and h7/h8 to s6. h8 is the modeled management host.
- Block, allow, aggregate rate-limit, priority scheduling, waypoint/avoided-link rerouting and latency constraints. Directional selectors by host, application, transport and destination port.
- Constrained offline intent compiler, explicitly **not an LLM**. Optional Google Gemini JSON translation, never generated shell commands.
- Strict allow-listed JSON, management protection, overlapping-policy conflict checks, route feasibility, propagation-bound feasibility, isolated dry runs and explicit approval.
- Configuration revision and expiring proposal binding. Duplicate apply requests do not duplicate policies. Versioned rollback of policies, link states and settings.
- Reactive path recomputation, forecast-aware path weights with hysteresis/hold-down, latency-aware routing, modeled telemetry and capacity-conserving priority scheduling.
- Visitor-isolated sessions, CSRF checks, same-origin requests, bounded body size/session count/history/threads, API quotas and security headers.

## A five-minute demonstration

1. Open the app in **Offline compiler** mode. Enter `Prioritize video and block p2p`.
2. Click **Validate & preview**, review the structured rules and modeled before/after effects, then **Approve & apply**.
3. Open **Policy registry** to see the two approved rules. In **Traffic explorer**, p2p is blocked separately from congestion drops.
4. Back in the command center, select link `s1-s3`, choose **Inject failure**, and confirm. The decision trace and active flow paths show reactive rerouting.
5. Increase traffic demand. Try forecast-aware routing. It is a heuristic, not a promise of improvement: the included congested-failure benchmark shows it can underperform reactive-only routing.
6. Open **Change history** to restore a snapshot. Export the session evidence as JSON.

Try `Limit h2 to 5 Mbps`, `Reroute h1 to h5 via s2`, `Block h1 to h3 on tcp port 80` or `Keep h1 to h5 latency under 30 ms`.

Try `Drop all traffic`, `Block controller` or an impossible one-millisecond latency ceiling. The app rejects unsafe or impossible changes without applying them. Unsupported offline wording is refused, not guessed.

## Optional Google free API

Set `GEMINI_API_KEY` only in the server's environment or host secret manager, never in source code, browser storage or the frontend. Set `GEMINI_FREE_TIER_CONFIRMED=true` only after verifying the key's project has no enabled billing and the selected model is on the free tier. The current default is `gemini-3.8-flash`, configurable with `GEMINI_MODEL`. Older 2.5 Flash returned a retirement error during testing. There is no paid-model or provider fallback.

Google API availability and rate limits can change. The UI reports failures honestly and keeps offline mode available. Gemini requests are limited to eight per visitor session, two concurrent requests and a shared default 50 calls/day ledger. Failed requests consume a reserved call to avoid retry storms. SQLite usage survives local server restarts but not ephemeral hosting resets; never enable billing on a public demo relying only on this ledger. The runtime does not enable billing itself.

Free-tier prompts may be used by Google to improve products. Do not enter secrets or private data. Current terms and rate limits should be checked at:
- https://ai.google.dev/gemini-api/docs/pricing
- https://ai.google.dev/gemini-api/docs/rate-limits

## Tests and reproducible evaluation

```bash
python -m unittest discover -s tests -v
python tests/evaluate.py
```

The test suite has 32 test methods, including a 60-case valid offline vocabulary matrix, unsafe/ambiguous cases, schema/safety checks, conflict rejection, idempotency, stale/expired approval, rollback, deterministic flow accounting, model failure recovery, static-model failure, HTTP/CSRF/session/body limits and isolation. These are **not** an LLM accuracy benchmark.

The optional developer-only browser test requires Playwright and local Chromium. It exercises the actual frontend/backend through the browser:

```bash
python -m pip install playwright
python tests/browser_smoke.py
```

It verifies approval, registry, fault injection, flow explorer, rollback, unsafe rejection, isolation and mobile layout. The test script's Chrome path may need adjusting on another OS. See `docs/VERIFICATION.md` for actual test evidence, `docs/model-evaluation.json` for computed model results, and `docs/MODEL.md` for assumptions.

## Hosting

`render.yaml` describes a free Render web service. It binds `HOST=0.0.0.0`, reads the host-provided `PORT`, and runs tests during build. Keep the repository private and authorize only this repository to the deployment service. The app works without a Google key.

Render free instances can sleep after 15 idle minutes and cold-start on the next visit. Sessions and the local quota database are ephemeral and reset on sleep, restart or redeploy. Free service limits are shared with other services in the workspace. No payment method is required for this app's configured plan. Do not upgrade or enable billing inadvertently. See https://render.com/docs/free .

## Source map

| File | Purpose |
|---|---|
| `core.py` | Policy schema/compiler, graph routing, dry run, snapshots, simulation |
| `server.py` | HTTP API, sessions, CSRF, server-side Gemini and quotas |
| `static/index.html` | Semantic dashboard layout and in-app explanation |
| `static/style.css` | Responsive visual system |
| `static/app.js` | API-driven SVG charts/topology and review controls |
| `tests/test_core.py` | Model and policy regression tests |
| `tests/test_http.py` | Real HTTP security and isolation tests |
| `tests/evaluate.py` | Repeatable synthetic comparison and forecasting metrics |
| `tests/browser_smoke.py` | Browser end-to-end checks |
| `docs/` | Architecture, model assumptions, API, scope and verification |

## Boundaries

This is an explainable educational demonstrator, not a production network controller or a guarantee against all malicious prompts. No authentication protects this public demo because visitors affect only their own disposable twin. Do not use `http.server` as a general production platform, store sensitive information in sessions, or point this app at real devices without a separate reviewed integration.

The proposal's real SDN/OpenFlow, OSPF comparison, trained LSTM, iperf/ping capture and physical packet benchmarks remain outside this delivered scope. No benchmark targets from the PDF are presented as achieved results. Use the provided explanations and actual evidence when presenting the project, and follow your course's AI-use and attribution rules.

## Live deployment

https://aether-network-twin.onrender.com/

Deployment evidence, free-host limits and current model status: [docs/deployment.md](docs/deployment.md).
