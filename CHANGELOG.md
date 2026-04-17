# ReconAI — Changelog

## v2.2.0 — Session 3 (Current)

### New Features
- `--diagnose` flag: full pre-scan health check (tools, Python packages, API keys, version detection)
- `--resume <dir>` flag: resume any interrupted/partial scan; reloads data, re-runs AI + reports
- `utils/diagnostics.py`: standalone diagnostics module with version detection for httpx, katana, gowitness
- Ctrl+C handling now prints `--resume` command to stdout so you can pick up where you left off
- D3.js fallback graph: if pyvis is not installed, a self-contained interactive HTML graph is generated
- Port nodes now appear in attack surface graph (colour-coded by interestingness)

### Bug Fixes
- `graph_generator.py` — **graph bug**: used `G.nodes()` (NetworkX) but nodes were added to pyvis `net`, not `G`, causing all host→url edges to be dropped silently. Fixed by tracking added nodes in a `set()`.
- `tools/executor.py` — **PATH extension**: Go binaries in `~/go/bin` and `~/.local/bin` are now added to `PATH` at startup; tools were silently "not found" when installed but not in shell PATH.
- `tools/executor.py` — **stderr noise**: recon tools emit informational stderr even on success; overly verbose stderr lines are now filtered before being surfaced as warnings.
- `modules/port_scanner.py` — **protocol stripping**: hosts with `https://` prefix passed to rustscan/nmap caused scan failures; protocols are now stripped before scanning.
- `modules/port_scanner.py` — **rustscan fallback**: rustscan returning empty output now triggers automatic nmap fallback instead of silently returning `{}`.
- `modules/port_scanner.py` — **nmap parser**: regex now handles both `hostname (ip)` and bare-IP host headers.
- `main.py` — **dotenv bootstrap**: `.env` is now loaded before any module imports that read env vars, fixing cases where API keys were not visible to the model router.
- `main.py` — **URL target stripping**: if user pastes `https://example.com` as target, protocol+path is stripped to bare domain.

### Improvements
- `vuln_hints.py` — expanded to 40+ rules; added 2025 CVEs: Next.js CVE-2025-29927, Tomcat CVE-2025-24813, Spring4Shell, Log4Shell, Confluence OGNL, GitLab RCE; added port-level hints for Docker API, Kubelet, Kubernetes API, MSSQL, Oracle
- `vuln_hints.py` — hint deduplication on `(target, hint_type)` key; all hints display in console summary during scan
- `port_scanner.py` — expanded INTERESTING_PORTS to 30+ services including Docker, K8s, Neo4j, Jenkins, MSSQL, Oracle, Zookeeper, Kafka
- `graph_generator.py` — open ports rendered as box-shaped nodes linked to their host

---

## v2.1.0 — Session 2

### Bug Fixes
- `modules/http_discovery.py` — `httpx -l` vs `-list` flag auto-detection; Python fallback rewired
- `core/model_router.py` — Gemini: dual SDK strategy (google-genai new + google-generativeai legacy); model mapping `gemini-1.5-pro` → `gemini-2.0-flash`
- `core/scope_parser.py` — explicit domain now implicitly covers all its subdomains
- `core/controller.py` — bare target always seeded into subdomain + resolved lists
- `modules/subdomain_enum.py` — dnsgen dual-mode (file arg + stdin pipe); dnsx fallback returns raw list
- `modules/endpoint_discovery.py` — katana v2 flag detection (`-jc`, `-nos`); gau flag detection
- `modules/screenshot_engine.py` — gowitness v2 vs v3 CLI auto-detection
- `modules/cloud_discovery.py` — httpx/httpcore INFO log suppression

---

## v2.0.0 — Session 1

Initial release: 12-phase autonomous recon pipeline, 4 LLM providers, interactive HTML graph, full report generation.
