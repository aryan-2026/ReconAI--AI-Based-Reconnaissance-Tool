#!/usr/bin/env python3
"""
ReconAI - Autonomous Hybrid Recon AI Agent
For Bug Bounty Hunting & Penetration Testing

Usage:
  python main.py                              # interactive
  python main.py --target example.com --model 3
  python main.py --target example.com --passive-only --no-screenshots
  python main.py --diagnose                  # check all tools & deps
  python main.py --resume /path/to/output    # resume partial scan
  python main.py --check-tools
"""
import asyncio
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# ── Bootstrap ─────────────────────────────────────────────────
# Must happen before any other imports that read env vars
_dotenv_loaded = False
try:
    from dotenv import load_dotenv
    _env_file = Path(__file__).parent / ".env"
    if _env_file.exists():
        load_dotenv(_env_file)
        _dotenv_loaded = True
except ImportError:
    pass   # dotenv missing; env vars may still be set in shell

sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import banner, console, section, info, warn, error, success
from core.config  import LLM_PROVIDERS, RECON_DATA_DIR
from core.model_router  import ModelRouter
from core.controller    import ReconController


# ══════════════════════════════════════════════════════════════
# Interactive prompts
# ══════════════════════════════════════════════════════════════

def select_model() -> str:
    console.print("\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│         SELECT AI MODEL PROVIDER         │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────┘[/bold cyan]\n")
    for pid, provider in LLM_PROVIDERS.items():
        key_env = provider.get("key_env")
        if key_env:
            has_key = bool(os.getenv(key_env))
            key_status = "[green]✔ key found[/green]" if has_key else "[red]✘ key missing[/red]"
        else:
            key_status = "[green]✔ local[/green]"
        console.print(
            f"  [bold white]{pid}[/bold white]. [cyan]{provider['name']}[/cyan] "
            f"([dim]{provider['model']}[/dim]) {key_status}"
        )
    while True:
        choice = console.input("\n[bold yellow]  Select model (1-4): [/bold yellow]").strip()
        if choice in LLM_PROVIDERS:
            return choice
        console.print("[red]  Invalid choice — enter 1, 2, 3 or 4.[/red]")


def get_target_info() -> dict:
    console.print("\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│           TARGET CONFIGURATION           │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────┘[/bold cyan]\n")
    while True:
        raw = console.input("  [bold]Target Domain[/bold] (e.g. example.com): ").strip().lower()
        if "://" in raw:
            from urllib.parse import urlparse
            raw = urlparse(raw).netloc or raw
        target = raw.split("/")[0].strip()
        if target and "." in target:
            break
        console.print("[red]  Please enter a valid domain (e.g. example.com)[/red]")

    console.print(f"\n  [dim]Scope examples: *.{target}, {target}[/dim]")
    scope_raw = console.input(
        f"  [bold]Scope[/bold] (comma-separated, Enter for *.{target},{target}): "
    ).strip()
    scope = scope_raw if scope_raw else f"*.{target},{target}"

    oos = console.input("  [bold]Out-of-Scope[/bold] (comma-separated, Enter to skip): ").strip()

    console.print("\n  [bold]Testing Mode:[/bold]")
    console.print("  1. Full Recon   (all modules, port scan, screenshots)")
    console.print("  2. Passive Only (no active scanning / no port scan)")
    console.print("  3. Quick Recon  (subdomain + HTTP only, no fuzzing)")
    test_type = (console.input("  Select (1-3, default=1): ").strip() or "1")

    return {
        "target":    target,
        "scope":     scope,
        "oos":       oos,
        "test_type": test_type if test_type in ("1", "2", "3") else "1",
    }


def get_permutation_choice(subdomain_count: int) -> str:
    """Ask user about permutation after enumeration with the real count."""
    est = max(subdomain_count * 30, 500)
    console.print(f"\n[bold yellow]  ⚡ Subdomain Permutation Engine[/bold yellow]")
    console.print(f"  Enumerated [cyan]{subdomain_count}[/cyan] subdomains.")
    console.print(f"  Permutation will fire ~{est:,} DNS queries.\n")
    console.print("  1. Full permutation  (all combos — slow)")
    console.print("  2. Limited           (fast / filtered)")
    console.print("  3. Skip              (recommended for small targets)")
    choice = (console.input("\n  [bold]Run permutation?[/bold] (1-3, default=3): ").strip() or "3")
    return {"1": "full", "2": "limited", "3": "skip"}.get(choice, "skip")


def build_options(test_type: str) -> dict:
    if test_type == "2":
        return {"port_scan": False, "screenshots": False,
                "active_fuzzing": False, "permutation_mode": "skip"}
    elif test_type == "3":
        return {"port_scan": False, "screenshots": True,
                "active_fuzzing": False, "permutation_mode": "skip"}
    else:
        return {"port_scan": True, "screenshots": True, "active_fuzzing": True}


# ══════════════════════════════════════════════════════════════
# Tool check (standalone or embedded)
# ══════════════════════════════════════════════════════════════

def check_tool_availability():
    import shutil
    section("Tool Availability Check")
    tools = {
        # Phase 2 — Subdomain Discovery
        "subfinder":    "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass":        "go install github.com/owasp-amass/amass/v4/...@master",
        "assetfinder":  "go install github.com/tomnomnom/assetfinder@latest",
        "chaos":        "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        # Phase 3/4 — DNS + Permutation
        "dnsx":         "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "dnsgen":       "pip install dnsgen",
        "altdns":       "pip install altdns",
        # Phase 5 — Port Scanning
        "rustscan":     "cargo install rustscan  OR  https://github.com/RustScan/RustScan/releases",
        "nmap":         "sudo apt install -y nmap",
        # Phase 6 — HTTP Discovery
        "httpx":        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        # Phase 7 — Screenshots
        "gowitness":    "go install github.com/sensepost/gowitness@latest",
        "EyeWitness":   "git clone https://github.com/RedSiege/EyeWitness && cd EyeWitness/Python && pip install -r requirements.txt",
        # Phase 9/11/12 — Endpoint & JS Discovery
        "katana":       "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "ffuf":         "go install github.com/ffuf/ffuf/v2@latest",
        "gau":          "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls":  "go install github.com/tomnomnom/waybackurls@latest",
        # Phase 10 — Secret Detection
        "trufflehog":   "go install github.com/trufflesecurity/trufflehog/v3@latest",
        "gitleaks":     "go install github.com/gitleaks/gitleaks/v8@latest",
        # Phase 11 — JS Endpoint Extraction
        "xnLinkFinder": "pip install xnLinkFinder",
        "linkfinder":   "pip install linkfinder",
        # Phase 15 — Cloud Discovery
        "cloud_enum":   "pip install cloud-enum",
        "cloudbrute":   "go install github.com/0xsha/CloudBrute@latest",
    }
    found, missing = [], []
    for tool, cmd in tools.items():
        if shutil.which(tool):
            found.append(tool)
        else:
            missing.append((tool, cmd))
    console.print(f"  [green]✔ Available ({len(found)}):[/green] {', '.join(found) or 'none'}")
    if missing:
        console.print(f"\n  [yellow]✘ Missing ({len(missing)}):[/yellow]")
        for tool, cmd in missing:
            console.print(f"    [dim]{tool}:[/dim]  [cyan]{cmd}[/cyan]")
    return len(found), len(missing)


# ══════════════════════════════════════════════════════════════
# Resume a partial scan
# ══════════════════════════════════════════════════════════════

async def resume_scan(output_dir_path: str, model_id: str = None):
    """
    Resume a partial/interrupted scan from an existing output directory.
    Reloads all saved data then re-runs AI analysis and report generation.
    """
    output_dir = Path(output_dir_path)
    if not output_dir.exists():
        error(f"Output directory not found: {output_dir}")
        sys.exit(1)

    # Try to determine target from existing report or directory name
    target = None
    report_path = output_dir / "final_report.json"
    if report_path.exists():
        try:
            import json
            report = json.loads(report_path.read_text())
            target = report.get("target") or report.get("meta", {}).get("target")
        except Exception:
            pass

    if not target:
        # Parse from directory name: "example_com_20240601_120000"
        parts = output_dir.name.split("_")
        if len(parts) >= 2:
            # Re-join all parts before the timestamp
            target = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]
            target = target.replace("_", ".")

    if not target:
        target = console.input("  [bold]Target domain (for resume): [/bold]").strip()

    console.print(f"\n  [bold cyan]Resuming scan for:[/bold cyan] {target}")
    console.print(f"  [dim]Output dir: {output_dir}[/dim]")

    if not model_id:
        model_id = select_model()

    try:
        model_router = ModelRouter(model_id)
    except EnvironmentError as e:
        error(str(e))
        sys.exit(1)

    from core.dataset_manager import DatasetManager
    dataset = DatasetManager(output_dir)
    dataset.set_target(target)
    dataset.load_from_files()

    section("Resuming — Re-running AI Analysis & Reports")
    recon_data = dataset.get()

    # Re-run vuln hints on existing data
    from modules.vuln_hints import VulnHintEngine
    hints = VulnHintEngine(output_dir).analyze(recon_data)
    dataset.update("vulnerability_hints", hints)

    # Re-run AI analysis
    import json
    ai_input = {
        "target":           target,
        "subdomains_count": len(recon_data.get("subdomains", [])),
        "live_hosts":       recon_data.get("live_hosts", [])[:30],
        "cloud_assets":     recon_data.get("cloud_assets", [])[:20],
        "critical_hints":   [h for h in hints if h.get("priority") == "CRITICAL"][:15],
        "high_hints":       [h for h in hints if h.get("priority") == "HIGH"][:15],
        "endpoints_count":  len(recon_data.get("endpoints", [])),
        "js_secrets_count": len(recon_data.get("js_secrets", [])),
    }
    try:
        ai_analysis = model_router.analyze_recon_data(ai_input)
        dataset.update("ai_analysis", ai_analysis)
        success("AI analysis complete")
    except Exception as e:
        warn(f"AI analysis failed: {e}")
        ai_analysis = {}

    # Regenerate graph
    from modules.graph_generator import AttackSurfaceGraph
    AttackSurfaceGraph(output_dir).generate(target, dataset.get())

    # Final report
    dataset.generate_final_report(ai_analysis)
    console.print(f"\n[bold green]  ✅ Resume complete → {output_dir}[/bold green]\n")


# ══════════════════════════════════════════════════════════════
# CLI arg parser
# ══════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="ReconAI — Autonomous Bug Bounty Recon Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --target example.com --model 3
  python main.py --target example.com --scope "*.example.com,example.com" --model 2
  python main.py --target example.com --passive-only
  python main.py --diagnose
  python main.py --resume ./recon-data/example_com_20240601_120000
  python main.py --check-tools
        """
    )
    p.add_argument("--target",          help="Target domain")
    p.add_argument("--scope",           help="In-scope (comma-separated)")
    p.add_argument("--oos",             help="Out-of-scope (comma-separated)", default="")
    p.add_argument("--model",           help="LLM: 1=OpenAI 2=Claude 3=Gemini 4=Local", default=None)
    p.add_argument("--output",          help="Output directory", default=None)
    p.add_argument("--passive-only",    action="store_true", dest="passive_only")
    p.add_argument("--no-port-scan",    action="store_true", dest="no_port_scan")
    p.add_argument("--no-screenshots",  action="store_true", dest="no_screenshots")
    p.add_argument("--check-tools",     action="store_true", dest="check_tools")
    p.add_argument("--diagnose",        action="store_true",
                   help="Run full diagnostics (tools, packages, env, versions)")
    p.add_argument("--resume",          metavar="OUTPUT_DIR",
                   help="Resume interrupted scan from existing output dir")
    return p.parse_args()


# ══════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════

async def main():
    banner()
    args = parse_args()

    # ── Special modes ──────────────────────────────────────────
    if args.check_tools:
        check_tool_availability()
        return

    if args.diagnose:
        from utils.diagnostics import run_diagnostics
        run_diagnostics()
        return

    if args.resume:
        await resume_scan(args.resume, args.model)
        return

    # ── Normal scan flow ───────────────────────────────────────
    found_count, _ = check_tool_availability()
    if found_count == 0:
        console.print("\n[bold red]  ⚠ No recon tools found — running in Python-fallback mode.[/bold red]")
        console.print("  [dim]Run --check-tools to see install commands.[/dim]")

    # Model selection
    model_id = (args.model if args.model in LLM_PROVIDERS else None) or select_model()
    try:
        model_router = ModelRouter(model_id)
    except EnvironmentError as e:
        error(str(e))
        console.print("  [dim]Add your API key to .env (copy from .env.example)[/dim]")
        sys.exit(1)

    # Target configuration
    if args.target:
        raw_target = args.target.lower()
        if "://" in raw_target:
            from urllib.parse import urlparse
            raw_target = urlparse(raw_target).netloc or raw_target
        target = raw_target.split("/")[0].strip()
        target_info = {
            "target":    target,
            "scope":     args.scope or f"*.{target},{target}",
            "oos":       args.oos or "",
            "test_type": "2" if args.passive_only else "1",
        }
    else:
        target_info = get_target_info()

    # Options
    options = build_options(target_info["test_type"])
    if args.no_port_scan:
        options["port_scan"] = False
    if args.no_screenshots:
        options["screenshots"] = False

    # Permutation mode:
    # - Full interactive mode with no --target arg → ask AFTER enumeration (sentinel)
    # - CLI mode or non-full → skip
    if target_info["test_type"] == "1" and not args.target:
        options["permutation_mode"] = "ask"
    else:
        options.setdefault("permutation_mode", "skip")

    # Output directory
    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_clean = target_info["target"].replace(".", "_")
    output_dir   = Path(args.output) if args.output else RECON_DATA_DIR / f"{target_clean}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Confirm
    console.print("\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│              RECON SUMMARY               │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
    console.print(f"  Target:      [bold]{target_info['target']}[/bold]")
    console.print(f"  Scope:       [cyan]{target_info['scope']}[/cyan]")
    console.print(f"  OOS:         [dim]{target_info['oos'] or 'None'}[/dim]")
    console.print(f"  AI Model:    [green]{model_router.name}[/green]")
    console.print(f"  Output:      [dim]{output_dir}[/dim]")
    console.print(f"  Port Scan:   {'[green]YES[/green]' if options.get('port_scan')   else '[yellow]NO[/yellow]'}")
    console.print(f"  Screenshots: {'[green]YES[/green]' if options.get('screenshots') else '[yellow]NO[/yellow]'}")

    confirm = console.input("\n  [bold yellow]Start recon? (y/N): [/bold yellow]").strip().lower()
    if confirm not in ("y", "yes"):
        console.print("  [dim]Aborted.[/dim]")
        return

    # Run
    controller = ReconController(
        target       = target_info["target"],
        scope        = target_info["scope"],
        out_of_scope = target_info["oos"],
        model_router = model_router,
        output_dir   = output_dir,
        options      = options,
    )

    try:
        await controller.run()
        console.print("\n[bold green]  🎯 RECON MISSION COMPLETE![/bold green]\n")
    except KeyboardInterrupt:
        warn("\nInterrupted — saving partial data...")
        try:
            controller.dataset.load_from_files()
            controller.dataset.generate_final_report()
            console.print(f"  [dim]Partial report saved → {output_dir}[/dim]")
            console.print(f"  [dim]Resume later with: python main.py --resume {output_dir} --model {model_id}[/dim]")
        except Exception as e:
            warn(f"Could not save partial report: {e}")
    except Exception as e:
        error(f"Recon failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
