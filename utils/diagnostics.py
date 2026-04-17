"""
ReconAI - Diagnostics Module
Tests every tool and dependency before a real scan.
Shows exactly what will work and what needs fixing.
"""
import subprocess
import shutil
import sys
import importlib
from pathlib import Path
from utils.logger import console, section, success, warn, error, info


# ─────────────────────────────────────────────────────────────
# Expected tools with install commands
# ─────────────────────────────────────────────────────────────
TOOLS = {
    "subfinder":   ("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",   "Subdomain enumeration"),
    "amass":       ("go install github.com/owasp-amass/amass/v4/...@master",                      "Subdomain enumeration"),
    "assetfinder": ("go install github.com/tomnomnom/assetfinder@latest",                         "Subdomain enumeration"),
    "httpx":       ("go install github.com/projectdiscovery/httpx/cmd/httpx@latest",              "HTTP service discovery"),
    "dnsx":        ("go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",                "DNS resolution"),
    "ffuf":        ("go install github.com/ffuf/ffuf/v2@latest",                                  "Directory/API fuzzing"),
    "katana":      ("go install github.com/projectdiscovery/katana/cmd/katana@latest",            "Web crawling"),
    "gau":         ("go install github.com/lc/gau/v2/cmd/gau@latest",                            "Historical URLs"),
    "waybackurls": ("go install github.com/tomnomnom/waybackurls@latest",                         "Wayback Machine URLs"),
    "gowitness":   ("go install github.com/sensepost/gowitness@latest",                           "Screenshots"),
    "nmap":        ("sudo apt install -y nmap",                                                    "Port scanning"),
    "rustscan":    ("cargo install rustscan  OR  download from github.com/RustScan/RustScan",     "Fast port scanning"),
    "dnsgen":      ("pip install dnsgen",                                                          "Subdomain permutation"),
    "trufflehog":  ("go install github.com/trufflesecurity/trufflehog/v3@latest",                "Secret scanning"),
}

PYTHON_DEPS = {
    "openai":          "pip install openai",
    "anthropic":       "pip install anthropic",
    "google.genai":    "pip install google-genai",
    "httpx":           "pip install httpx",
    "rich":            "pip install rich",
    "dotenv":          "pip install python-dotenv",
    "networkx":        "pip install networkx",
    "pyvis":           "pip install pyvis",
    "jsbeautifier":    "pip install jsbeautifier",
    "bs4":             "pip install beautifulsoup4",
    "dns":             "pip install dnspython",
    "pydantic":        "pip install pydantic",
}


def run_diagnostics(verbose: bool = False) -> dict:
    """
    Run full diagnostics and return results dict.
    """
    section("ReconAI Diagnostics")
    results = {
        "tools_found":    [],
        "tools_missing":  [],
        "python_ok":      [],
        "python_missing": [],
        "env_ok":         [],
        "env_missing":    [],
        "issues":         [],
        "ready":          False,
    }

    # ── External tools ────────────────────────────────────────
    console.print("\n[bold cyan]  External Tools:[/bold cyan]")
    for tool, (install_cmd, description) in TOOLS.items():
        path = shutil.which(tool)
        if path:
            # Get version string
            try:
                ver_result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True, text=True, timeout=3
                )
                ver = (ver_result.stdout + ver_result.stderr).splitlines()
                ver_str = next((l for l in ver if l.strip()), "").strip()[:50]
            except Exception:
                ver_str = path
            results["tools_found"].append(tool)
            console.print(f"  [green]  ✔ {tool:<15}[/green] [dim]{ver_str}[/dim]")
        else:
            results["tools_missing"].append(tool)
            results["issues"].append(f"Missing tool: {tool} ({description})")
            console.print(f"  [red]  ✘ {tool:<15}[/red] [dim]Install: {install_cmd}[/dim]")

    # ── Python packages ───────────────────────────────────────
    console.print("\n[bold cyan]  Python Packages:[/bold cyan]")
    for pkg, install_cmd in PYTHON_DEPS.items():
        try:
            importlib.import_module(pkg)
            results["python_ok"].append(pkg)
            console.print(f"  [green]  ✔ {pkg:<20}[/green]")
        except ImportError:
            results["python_missing"].append(pkg)
            results["issues"].append(f"Missing Python package: {pkg}")
            console.print(f"  [red]  ✘ {pkg:<20}[/red] [dim]{install_cmd}[/dim]")

    # ── Environment variables ─────────────────────────────────
    import os
    console.print("\n[bold cyan]  API Keys (.env):[/bold cyan]")
    env_vars = {
        "OPENAI_API_KEY":    "OpenAI",
        "ANTHROPIC_API_KEY": "Claude",
        "GEMINI_API_KEY":    "Gemini",
    }
    for var, name in env_vars.items():
        val = os.getenv(var, "")
        if val and len(val) > 10:
            results["env_ok"].append(var)
            console.print(f"  [green]  ✔ {name:<15}[/green] [dim]{val[:8]}...{val[-4:]}[/dim]")
        else:
            results["env_missing"].append(var)
            console.print(f"  [yellow]  ○ {name:<15}[/yellow] [dim]not set (optional if using other provider)[/dim]")

    # Check Ollama
    ollama_running = False
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        ollama_running = True
        results["env_ok"].append("OLLAMA")
        console.print(f"  [green]  ✔ Ollama         [/green] [dim]running at localhost:11434[/dim]")
    except Exception:
        console.print(f"  [yellow]  ○ Ollama         [/yellow] [dim]not running (optional)[/dim]")

    # ── Wordlists ─────────────────────────────────────────────
    console.print("\n[bold cyan]  Wordlists:[/bold cyan]")
    wl_paths = [
        Path("/usr/share/seclists"),
        Path("/usr/share/wordlists"),
    ]
    seclists_found = False
    for p in wl_paths:
        if p.exists():
            seclists_found = True
            console.print(f"  [green]  ✔ SecLists       [/green] [dim]{p}[/dim]")
            break
    if not seclists_found:
        console.print(f"  [yellow]  ○ SecLists       [/yellow] [dim]not found — fallback wordlists will be used[/dim]")
        console.print(f"  [dim]    Install: sudo apt install seclists[/dim]")

    # ── httpx flag detection ──────────────────────────────────
    console.print("\n[bold cyan]  Tool Version Checks:[/bold cyan]")
    if shutil.which("httpx"):
        try:
            r = subprocess.run(["httpx", "-help"], capture_output=True, text=True, timeout=5)
            flag = "-l" if "-l " in (r.stdout + r.stderr) else "-list"
            console.print(f"  [green]  ✔ httpx flag     [/green] [dim]uses {flag}[/dim]")
        except Exception:
            console.print(f"  [yellow]  ? httpx flag     [/yellow] [dim]could not detect[/dim]")

    if shutil.which("katana"):
        try:
            r = subprocess.run(["katana", "-version"], capture_output=True, text=True, timeout=5)
            ver_out = r.stdout + r.stderr
            if "2." in ver_out:
                console.print(f"  [green]  ✔ katana v2      [/green] [dim]flags: -jc -nos[/dim]")
            else:
                console.print(f"  [green]  ✔ katana v1      [/green] [dim]flags: -js-crawl -no-scope-check[/dim]")
        except Exception:
            pass

    if shutil.which("gowitness"):
        try:
            r = subprocess.run(["gowitness", "version"], capture_output=True, text=True, timeout=5)
            ver_out = (r.stdout + r.stderr).lower()
            v = "v3" if ("version 3" in ver_out or " v3." in ver_out) else "v2"
            console.print(f"  [green]  ✔ gowitness      [/green] [dim]{v} detected[/dim]")
        except Exception:
            pass

    # ── Summary ───────────────────────────────────────────────
    console.print("\n[bold cyan]  Summary:[/bold cyan]")
    t_found   = len(results["tools_found"])
    t_total   = len(TOOLS)
    py_found  = len(results["python_ok"])
    py_total  = len(PYTHON_DEPS)
    api_found = len(results["env_ok"])

    console.print(f"  Tools:      [green]{t_found}[/green]/{t_total} available")
    console.print(f"  Python:     [green]{py_found}[/green]/{py_total} packages installed")
    console.print(f"  API keys:   [green]{api_found}[/green] configured")

    # Minimum viability check
    min_tools_needed  = {"httpx", "dnsx"}
    min_python_needed = {"httpx", "rich", "dotenv", "pydantic"}
    has_min_tools  = bool(min_tools_needed.intersection(set(results["tools_found"])))
    has_min_python = bool(min_python_needed.issubset(set(results["python_ok"])))
    has_api        = len(results["env_ok"]) > 0

    results["ready"] = has_min_python  # Can run in fallback mode without tools

    if results["ready"]:
        console.print("\n  [bold green]✅ ReconAI can run (some tools may be limited)[/bold green]")
    else:
        console.print("\n  [bold red]❌ Critical Python dependencies missing — run: pip install -r requirements.txt[/bold red]")

    if not has_api:
        console.print("  [yellow]  ⚠ No API keys set — select Local LLM (option 4)[/yellow]")

    return results
