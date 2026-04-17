"""
ReconAI - Configuration
Central config: LLM providers, tool paths, phase constants, priority keywords.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).parent.parent / ".env")

# ── Directory layout ───────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.parent
WORDLIST_DIR  = BASE_DIR / "wordlists"
RECON_DATA_DIR = BASE_DIR / "recon-data"

RECON_DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── LLM Provider definitions ───────────────────────────────────
LLM_PROVIDERS = {
    "1": {
        "name":    "OpenAI GPT-4o",
        "model":   "gpt-4o",
        "key_env": "OPENAI_API_KEY",
    },
    "2": {
        "name":    "Claude (Anthropic)",
        "model":   "claude-opus-4-5",
        "key_env": "ANTHROPIC_API_KEY",
    },
    "3": {
        "name":    "Gemini",
        "model":   "gemini-2.0-flash",
        "key_env": "GEMINI_API_KEY",
    },
    "4": {
        "name":    "Local LLM (Ollama)",
        "model":   "llama3",
        "key_env": None,
    },
}

# ── Tool paths (overridable via .env) ──────────────────────────
TOOL_PATHS = {
    # Phase 2 — Subdomain Discovery
    "subfinder":    os.getenv("SUBFINDER_PATH",   "subfinder"),
    "amass":        os.getenv("AMASS_PATH",        "amass"),
    "assetfinder":  os.getenv("ASSETFINDER_PATH",  "assetfinder"),
    "chaos":        os.getenv("CHAOS_PATH",        "chaos"),
    # Phase 3/4 — DNS + Permutation
    "dnsx":         os.getenv("DNSX_PATH",         "dnsx"),
    "dnsgen":       os.getenv("DNSGEN_PATH",       "dnsgen"),
    "altdns":       os.getenv("ALTDNS_PATH",       "altdns"),
    # Phase 5 — Port Scanning
    "rustscan":     os.getenv("RUSTSCAN_PATH",     "rustscan"),
    "nmap":         os.getenv("NMAP_PATH",         "nmap"),
    # Phase 6 — HTTP
    "httpx":        os.getenv("HTTPX_PATH",        "httpx"),
    # Phase 7 — Screenshots
    "gowitness":    os.getenv("GOWITNESS_PATH",    "gowitness"),
    "EyeWitness":   os.getenv("EYEWITNESS_PATH",   "EyeWitness"),
    # Phase 9/11/12 — Endpoint & JS Discovery
    "katana":       os.getenv("KATANA_PATH",       "katana"),
    "ffuf":         os.getenv("FFUF_PATH",         "ffuf"),
    "gau":          os.getenv("GAU_PATH",          "gau"),
    "waybackurls":  os.getenv("WAYBACKURLS_PATH",  "waybackurls"),
    # Phase 10 — Secrets
    "trufflehog":   os.getenv("TRUFFLEHOG_PATH",  "trufflehog"),
    "gitleaks":     os.getenv("GITLEAKS_PATH",     "gitleaks"),
    # Phase 11 — JS Endpoints
    "xnLinkFinder": os.getenv("XNLINKFINDER_PATH","xnLinkFinder"),
    "linkfinder":   os.getenv("LINKFINDER_PATH",   "linkfinder"),
    # Phase 15 — Cloud
    "cloud_enum":   os.getenv("CLOUDENUM_PATH",   "cloud_enum"),
    "cloudbrute":   os.getenv("CLOUDBRUTE_PATH",  "cloudbrute"),
}

# ── Chaos API key ──────────────────────────────────────────────
CHAOS_API_KEY = os.getenv("CHAOS_API_KEY", "")

# ── Priority scoring keywords ──────────────────────────────────
PRIORITY_KEYWORDS = {
    "critical": [
        "admin", "administrator", "root", "superuser", "shell",
        "database", "db", "mysql", "postgres", "redis", "mongodb",
        "backup", "config", "secret", "private", "internal",
    ],
    "high": [
        "api", "auth", "login", "dashboard", "panel", "manage",
        "upload", "download", "files", "dev", "staging", "test",
        "graphql", "swagger", "jenkins", "kibana", "grafana",
    ],
    "medium": [
        "app", "portal", "service", "system", "data", "user",
        "account", "profile", "settings", "docs", "help",
    ],
}
