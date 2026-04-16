# ReconAI — Autonomous Bug Bounty Recon Agent

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
```

> **ReconAI** is a fully autonomous, 18-phase bug bounty reconnaissance agent.
> It combines 20+ industry-standard recon tools with AI-powered analysis
> (OpenAI, Claude, Gemini, or Local LLM) to map the complete attack surface
> of a target — automatically.

---

## IMPORTANT — Before You Start

> **Switch to root before installing or running anything.**

```bash
sudo su
```

All installation commands and tool setups in this guide must be run as **root**
to avoid permission errors with Go binaries, apt packages, and system PATH changes.

---

## Table of Contents

1. [Features](#features)
2. [18-Phase Recon Pipeline](#18-phase-recon-pipeline)
3. [Prerequisites](#prerequisites)
4. [PATH Setup Required](#path-setup-required)
5. [Installation](#installation)
6. [Manual Tool Installation](#manual-tool-installation)
7. [API Key Configuration](#api-key-configuration)
8. [Usage](#usage)
9. [Output Files](#output-files)
10. [Tool Reference](#tool-reference)
11. [Troubleshooting](#troubleshooting)
12. [Legal Disclaimer](#legal-disclaimer)
13. [Project Structure](#project-structure)

---

## Features

- **18-phase autonomous pipeline** from scope parsing to final scored report
- **4 AI providers** — OpenAI GPT-4o, Claude Opus, Gemini Flash, or local Ollama LLM
- **10+ recon tools** — all integrated, version-aware, with graceful fallbacks
- **Parallel execution** — subdomain tools, DNS resolution, and cloud probing run concurrently
- **Hybrid secret detection** — TruffleHog + gitleaks + 18 regex patterns
- **API schema extraction** — auto-detects swagger, openapi, graphql, Spring actuator
- **Interactive attack surface graph** — pyvis HTML graph + D3.js fallback
- **Resume interrupted scans** — `--resume` flag reloads partial data and continues
- **Built for Kali Linux** — tested on Kali, works on Ubuntu/Debian

---

## 18-Phase Recon Pipeline

```
Phase  1 — Scope Processing
           Input: target domain + scope rules
           Output: scope_domains.txt

Phase  2 — Parallel Subdomain Discovery
           Tools: subfinder | amass | assetfinder | chaos
           Output: subdomains_raw.txt

Phase  3 — DNS Resolution
           Tool: dnsx
           Output: resolved_subdomains.txt

Phase  4 — Subdomain Permutation (user-prompted after Phase 3)
           Tools: dnsgen + altdns  then  dnsx re-resolve
           Output: permutations.txt → valid_permutations.txt (merged back)

Phase  5 — Port Scanning
           Tools: rustscan → nmap fallback
           Output: open_ports.txt / open_ports.json

Phase  6 — HTTP Service Discovery
           Tool: httpx (input = open_ports.txt)
           Output: live_hosts.txt / live_hosts.json

Phase  7 — Screenshot Recon + AI Classification
           Tools: gowitness + EyeWitness
           AI classifies: login portals, admin panels, monitoring, dev envs
           Output: screenshots/

Phase  8 — Technology Fingerprinting
           Source: httpx -tech-detect output
           Output: technology inventory

Phase  9 — JavaScript Discovery
           Tool: katana -extension-match js
           Output: js_urls.txt

Phase 10 — JavaScript Secret Detection
           Tools: TruffleHog + gitleaks + regex patterns
           Output: js_secrets.json / js_secrets.txt

Phase 11 — JavaScript Endpoint Extraction
           Tools: xnLinkFinder + LinkFinder + regex
           Output: js_endpoints.txt

Phase 12 — Endpoint Discovery
           Tools: katana (crawl) + ffuf (brute) + gau + waybackurls
           Output: endpoints.txt

Phase 13 — API Schema Extraction
           Probes: swagger.json, openapi.json, graphql introspection, api-docs
           Output: api_schema.json

Phase 14 — API Discovery
           Methods: crawl + historical URLs + wordlist fuzzing
           Output: api_endpoints.txt

Phase 15 — Cloud Asset Discovery
           Tools: custom HTTP probes + CloudEnum + CloudBrute
           Platforms: AWS S3, GCP, Azure Blob, Firebase
           Output: cloud_assets.json / cloud_assets.txt

Phase 16 — Vulnerability Hint Detection
           40+ rules covering ports, technologies, endpoints, secrets, CVEs
           Output: vulnerability_hints.json

Phase 17 — Attack Surface Graph
           Output: attack_surface_graph.html (interactive pyvis or D3.js)

Phase 18 — Priority Target Identification + Final Report
           AI scores each asset 1-10, ranks all findings
           Output: final_report.json / report.md
```

---

## PATH Setup Required

> Run these commands as root (`sudo su`) **before** installing any tools.
> Without this, Go-installed binaries will not be found in your PATH.

```bash
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

If you are using **bash** instead of zsh:

```bash
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Verify Go is accessible:

```bash
go version
# Expected output: go version go1.22.x linux/amd64
```

---

## Installation

### Step 1 — Switch to root

```bash
sudo su
```

### Step 2 — Extract the project

```bash
unzip reconai_v3.0.zip
cd reconai
```

### Step 3 — Set PATH (if not done already)

```bash
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

### Step 4 — Run the setup script

```bash
chmod +x setup.sh
./setup.sh
```

The setup script will automatically:

- Install system packages: `nmap`, `chromium-browser`, `git`, `curl`, `wget`, `build-essential`
- Install Go 1.22 if not already present
- Install all Go-based recon tools via `go install`
- Install RustScan via cargo or pre-built `.deb` package
- Create a Python virtual environment and install all Python dependencies
- Install `dnsgen`, `altdns`, `cloud-enum`, and other pip tools
- Download and configure SecLists wordlists
- Create `.env` from `.env.example`

### Step 5 — Activate the virtual environment

```bash
source venv/bin/activate
```

### Step 6 — Configure API keys

```bash
cp .env.example .env
nano .env
```

Fill in your API keys (see API Key Configuration section below).

### Step 7 — Verify installation

```bash
# Check which tools are installed
python main.py --check-tools

# Run full diagnostics
python main.py --diagnose
```

### Step 8 — Run ReconAI

```bash
python main.py
```

---

## Manual Tool Installation

> If `setup.sh` fails to install any tool, use the commands below to install it manually.
> All commands must be run as root.
> ReconAI will warn you when a tool is missing but will continue with available tools.

### PATH — Set first before installing anything

```bash
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
```

### Phase 2 — Subdomain Discovery

```bash
# subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# amass
go install github.com/owasp-amass/amass/v4/...@master
# If go install fails for amass:
snap install amass
# Or:
apt install amass

# assetfinder
go install github.com/tomnomnom/assetfinder@latest

# chaos (requires free API key from chaos.projectdiscovery.io)
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

### Phase 3 and 4 — DNS Resolution and Permutation

```bash
# dnsx
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# dnsgen
pip install dnsgen

# altdns
pip install altdns
```

### Phase 5 — Port Scanning

```bash
# nmap
apt install -y nmap

# rustscan — Option 1: cargo
apt install -y cargo
cargo install rustscan

# rustscan — Option 2: pre-built deb
wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb
dpkg -i rustscan_amd64.deb
```

### Phase 6 — HTTP Discovery

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Phase 7 — Screenshots

```bash
# gowitness
go install github.com/sensepost/gowitness@latest

# EyeWitness
git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness
cd /opt/EyeWitness/Python
pip install -r requirements.txt
ln -s /opt/EyeWitness/Python/EyeWitness.py /usr/local/bin/EyeWitness
chmod +x /usr/local/bin/EyeWitness
```

### Phase 9, 11, 12 — Crawling and Endpoint Discovery

```bash
# katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# ffuf
go install github.com/ffuf/ffuf/v2@latest

# gau
go install github.com/lc/gau/v2/cmd/gau@latest

# waybackurls
go install github.com/tomnomnom/waybackurls@latest
```

### Phase 10 — Secret Detection

```bash
# TruffleHog
go install github.com/trufflesecurity/trufflehog/v3@latest

# gitleaks
go install github.com/gitleaks/gitleaks/v8@latest
```

### Phase 11 — JS Endpoint Extraction

```bash
# xnLinkFinder
pip install xnLinkFinder

# LinkFinder
pip install linkfinder
```

### Phase 15 — Cloud Asset Discovery

```bash
# cloud_enum
pip install cloud-enum

# CloudBrute
go install github.com/0xsha/CloudBrute@latest
```

### All Python dependencies at once

```bash
source venv/bin/activate
pip install -r requirements.txt
pip install google-genai
pip install dnsgen altdns xnLinkFinder linkfinder cloud-enum
```

---

## API Key Configuration

Edit the `.env` file in the project root:

```bash
nano .env
```

```
# LLM Provider Keys — at least one is required
OPENAI_API_KEY=sk-...your-openai-key...
ANTHROPIC_API_KEY=sk-ant-...your-claude-key...
GEMINI_API_KEY=AIza...your-gemini-key...

# Local LLM — no key needed, requires Ollama running
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Chaos Dataset API Key — optional, from chaos.projectdiscovery.io
CHAOS_API_KEY=your-chaos-key-here

# Rate Limiting
DNS_THREADS=100
HTTP_THREADS=50
FFUF_RATE=150
PORT_SCAN_RATE=1000
```

### Where to get API keys

| Provider | Link |
|----------|------|
| OpenAI | https://platform.openai.com/api-keys |
| Anthropic (Claude) | https://console.anthropic.com |
| Google Gemini | https://aistudio.google.com/app/apikey |
| ProjectDiscovery (Chaos) | https://chaos.projectdiscovery.io |

> If you have no API key, select option 4 (Local LLM) at startup and install Ollama first.

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
ollama serve
```

---

## Usage

### Interactive Mode (recommended for first run)

```bash
source venv/bin/activate
python main.py
```

You will be prompted for:
1. AI model selection (OpenAI / Claude / Gemini / Local)
2. Target domain
3. Scope definition
4. Out-of-scope domains
5. Testing mode (Full / Passive-only / Quick)
6. Permutation mode — shown after Phase 3 with the real subdomain count


## Output Files

All output is saved to `./recon-data/<target>_<timestamp>/`

```
recon-data/
└── example_com_20240601_120000/
    ├── scope_domains.txt           Phase 1  — in-scope domain list
    ├── subdomains_raw.txt          Phase 2  — all discovered subdomains
    ├── resolved_subdomains.txt     Phase 3  — DNS-resolved subdomains
    ├── permutations.txt            Phase 4  — permutation candidates (if run)
    ├── valid_permutations.txt      Phase 4  — validated permutations (if run)
    ├── open_ports.txt              Phase 5  — open ports flat list
    ├── open_ports.json             Phase 5  — open ports structured
    ├── live_hosts.txt              Phase 6  — live HTTP services URLs
    ├── live_hosts.json             Phase 6  — live hosts with full metadata
    ├── screenshots/                Phase 7  — gowitness screenshots
    │   └── eyewitness/             Phase 7  — EyeWitness screenshots
    ├── screenshot_classification.json  Phase 7 — AI category + priority scores
    ├── js_urls.txt                 Phase 9  — JavaScript file URLs
    ├── js_files/                   Phase 9  — downloaded + beautified JS
    ├── js_secrets.json             Phase 10 — secrets (TruffleHog+gitleaks+regex)
    ├── js_secrets.txt              Phase 10 — secrets flat format
    ├── gitleaks_report.json        Phase 10 — raw gitleaks JSON output
    ├── js_endpoints.txt            Phase 11 — endpoints extracted from JS
    ├── xnlinkfinder_output.txt     Phase 11 — raw xnLinkFinder output
    ├── endpoints.txt               Phase 12 — all discovered endpoints
    ├── api_schema.json             Phase 13 — swagger/openapi/graphql schemas
    ├── api_endpoints.txt           Phase 14 — all API endpoints
    ├── cloud_assets.json           Phase 15 — cloud assets structured
    ├── cloud_assets.txt            Phase 15 — cloud assets flat
    ├── vulnerability_hints.json    Phase 16 — prioritised vulnerability hints
    ├── attack_surface_graph.html   Phase 17 — interactive visual graph
    ├── final_report.json           Phase 18 — full structured JSON report
    └── report.md                   Phase 18 — human-readable markdown report
```

---

## Tool Reference

| Tool | Phase | Purpose | Install Command |
|------|-------|---------|----------------|
| subfinder | 2 | Passive subdomain enum | `go install ...subfinder@latest` |
| amass | 2 | Passive subdomain enum | `go install ...amass/v4@master` |
| assetfinder | 2 | Passive subdomain enum | `go install ...assetfinder@latest` |
| chaos | 2 | ProjectDiscovery dataset | `go install ...chaos-client@latest` |
| dnsx | 3, 4 | DNS resolution + validation | `go install ...dnsx@latest` |
| dnsgen | 4 | Subdomain permutation | `pip install dnsgen` |
| altdns | 4 | Subdomain permutation | `pip install altdns` |
| rustscan | 5 | Fast port scanning | `cargo install rustscan` |
| nmap | 5 | Service fingerprinting | `apt install nmap` |
| httpx | 6 | HTTP service discovery | `go install ...httpx@latest` |
| gowitness | 7 | Screenshot capture | `go install ...gowitness@latest` |
| EyeWitness | 7 | Screenshot capture | `git clone RedSiege/EyeWitness` |
| katana | 9, 12 | Web crawling + JS discovery | `go install ...katana@latest` |
| trufflehog | 10 | Secret scanning | `go install ...trufflehog/v3@latest` |
| gitleaks | 10 | Secret scanning | `go install ...gitleaks/v8@latest` |
| xnLinkFinder | 11 | JS endpoint extraction | `pip install xnLinkFinder` |
| linkfinder | 11 | JS endpoint extraction | `pip install linkfinder` |
| ffuf | 12, 14 | Directory + API fuzzing | `go install ...ffuf/v2@latest` |
| gau | 12, 14 | Historical URLs (AlienVault+) | `go install ...gau/v2@latest` |
| waybackurls | 12, 14 | Wayback Machine URLs | `go install ...waybackurls@latest` |
| cloud_enum | 15 | Cloud asset enumeration | `pip install cloud-enum` |
| cloudbrute | 15 | Cloud asset brute force | `go install ...CloudBrute@latest` |

> If any tool fails to install via `setup.sh`, install it manually using the commands above.
> ReconAI will warn when a tool is missing but continues with what is available.
> No phase is completely blocked — each module has a Python-based fallback.

---

## Vulnerability Hints Coverage

Phase 16 analyzes all collected data against 40+ rules:

| Priority | Examples |
|----------|---------|
| CRITICAL | Redis/MongoDB/Elasticsearch open, `.env` exposed, `.git` exposed, Docker API unauthenticated, public S3/Firebase, Kubernetes API |
| HIGH | Admin panels, Jenkins script console, phpMyAdmin, login portals, file upload endpoints, MSSQL/PostgreSQL exposed |
| MEDIUM | API surfaces, Grafana default creds, WAF detected, Spring Boot actuator, dev environments |
| LOW | Missing security headers, clickjacking, CORS misconfiguration check |

CVEs covered in 2025 ruleset: Next.js CVE-2025-29927, Tomcat CVE-2025-24813, Spring4Shell CVE-2022-22965, Log4Shell CVE-2021-44228, Confluence CVE-2023-22515, GitLab CVE-2021-22205

---

## Troubleshooting

### Go tools not found after installation

```bash
# Reload PATH
source ~/.zshrc

# Or manually export
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Verify binaries exist
ls $HOME/go/bin/
```

### httpx wrong flag error (-l vs -list)

ReconAI auto-detects the correct flag by reading `httpx -help`.
If detection fails, check your httpx version:

```bash
httpx -version
httpx -help | grep -E "\-l\b|\-list"
```

### Permission denied

```bash
# Always run as root for recon tools
sudo su
python main.py
```

### Gemini API errors (404 model not found)

```bash
pip install google-genai --upgrade
# ReconAI uses gemini-2.0-flash with automatic model mapping
```

### amass hanging or too slow

amass passive mode has a 600-second timeout built in. For faster results:

```bash
python main.py --target example.com --model 1 --passive-only
```

### Port scan needs root

nmap SYN scans require root privileges:

```bash
sudo su
source venv/bin/activate
python main.py --target example.com
```

### Virtual environment not active

```bash
# Always activate before running
source venv/bin/activate
# Prompt should show (venv)
python main.py
```

### Resume a failed or interrupted scan

```bash
ls recon-data/
python main.py --resume recon-data/example_com_20240601_120000 --model 1
```

When you press Ctrl+C during a scan, ReconAI saves all data collected so far
and prints the exact `--resume` command to use.

---

## AI Model Selection Guide

| Option | Provider | Notes |
|--------|----------|-------|
| 1 | OpenAI GPT-4o | Most accurate, best structured JSON output |
| 2 | Claude Opus | Strong security reasoning, good for complex targets |
| 3 | Gemini Flash | Fast, generous free tier |
| 4 | Local Ollama | Fully offline, no cost, requires local setup |

---

## Legal Disclaimer

> ReconAI is intended for authorized security testing only.
> Only use this tool against systems you own or have explicit written permission to test.
> Unauthorized scanning is illegal and may violate computer crime laws in your jurisdiction.
> The authors are not responsible for any misuse or damage caused by this tool.

---

## Project Structure

```
reconai/
├── main.py                     Entry point — interactive and CLI modes
├── setup.sh                    Automated installer for all tools
├── requirements.txt            Python dependencies
├── .env.example                API key and config template
├── CHANGELOG.md                Version history
├── core/
│   ├── controller.py           18-phase pipeline orchestrator
│   ├── model_router.py         Multi-LLM router (OpenAI/Claude/Gemini/Ollama)
│   ├── scope_parser.py         Scope enforcement and domain filtering
│   ├── dataset_manager.py      Central data store and report generator
│   └── config.py               Tool paths, LLM config, constants
├── modules/
│   ├── subdomain_enum.py       Phase 2/3/4 — subfinder+amass+chaos+dnsgen+altdns
│   ├── port_scanner.py         Phase 5 — rustscan + nmap
│   ├── http_discovery.py       Phase 6 — httpx
│   ├── screenshot_engine.py    Phase 7 — gowitness + EyeWitness + AI classify
│   ├── js_analyzer.py          Phase 9/10/11 — katana+trufflehog+gitleaks+xnLinkFinder
│   ├── endpoint_discovery.py   Phase 12 — katana+ffuf+gau+waybackurls
│   ├── api_schema.py           Phase 13 — swagger+openapi+graphql introspection
│   ├── cloud_discovery.py      Phase 15 — CloudEnum+CloudBrute+custom HTTP probes
│   ├── vuln_hints.py           Phase 16 — 40+ rules + 2025 CVEs
│   └── graph_generator.py      Phase 17 — pyvis interactive graph + D3.js fallback
├── tools/
│   └── executor.py             Async subprocess runner with PATH extension
├── utils/
│   ├── logger.py               Rich colored terminal output
│   ├── diagnostics.py          Pre-scan health checker with version detection
│   └── wordlist_manager.py     Wordlist selection and management
└── wordlists/
    ├── subdomains/
    ├── directories/
    ├── api/
    ├── cloud/
    ├── permutations/
    └── resolvers/
```

---

*ReconAI — Built for modern bug bounty hunting*
