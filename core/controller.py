"""
ReconAI - Main Controller
Implements the full 18-phase recon pipeline per spec:

Phase  1 — Scope Processing
Phase  2 — Parallel Subdomain Discovery (subfinder + amass + assetfinder + chaos)
Phase  3 — DNS Resolution (dnsx)
Phase  4 — Subdomain Permutation (dnsgen + altdns) + re-resolve
Phase  5 — Port Scanning (rustscan → nmap)
Phase  6 — HTTP Service Discovery (httpx, input = open_ports.txt)
Phase  7 — Screenshot Recon + AI Classification (gowitness + eyewitness)
Phase  8 — Technology Fingerprinting (httpx tech-detect)
Phase  9 — JavaScript Discovery (katana -extension-match js)
Phase 10 — JavaScript Secret Detection (TruffleHog + gitleaks + regex)
Phase 11 — JavaScript Endpoint Extraction (xnLinkFinder + LinkFinder + regex)
Phase 12 — Endpoint Discovery (katana + ffuf + gau + waybackurls)
Phase 13 — API Schema Extraction (swagger + openapi + graphql introspection)
Phase 14 — API Discovery (crawl + historical + wordlist fuzzing)
Phase 15 — Cloud Asset Discovery (custom probes + CloudEnum + CloudBrute)
Phase 16 — Vulnerability Hint Detection
Phase 17 — Dataset Storage + Attack Surface Graph
Phase 18 — Priority Target Identification + Final Report
"""
import asyncio
import json
from pathlib import Path
from typing import List

from core.config       import BASE_DIR, WORDLIST_DIR, RECON_DATA_DIR
from core.model_router    import ModelRouter
from core.scope_parser    import ScopeParser
from core.dataset_manager import DatasetManager

from tools.executor import ToolExecutor

from modules.subdomain_enum     import SubdomainEnumerator
from modules.http_discovery     import HTTPDiscovery
from modules.port_scanner       import PortScanner
from modules.endpoint_discovery import EndpointDiscovery
from modules.js_analyzer        import JSAnalyzer
from modules.api_schema         import APISchemaExtractor
from modules.cloud_discovery    import CloudDiscovery
from modules.screenshot_engine  import ScreenshotEngine
from modules.vuln_hints         import VulnHintEngine
from modules.graph_generator    import AttackSurfaceGraph

from utils.logger import (
    log, banner, section, info, success, warn, error, stat, console
)


class ReconController:
    """
    Central orchestrator: 18-phase pipeline matching the ReconAI spec.
    All phases run in strict order. No phase is skipped.
    """

    def __init__(
        self,
        target:       str,
        scope:        str,
        out_of_scope: str,
        model_router: ModelRouter,
        output_dir:   Path,
        options:      dict = None,
    ):
        self.target       = target
        self.model_router = model_router
        self.output_dir   = output_dir
        self.options      = options or {}

        # Phase 1 — Scope Processing
        self.scope_parser = ScopeParser()
        self.scope_parser.parse(scope, out_of_scope)

        self.dataset  = DatasetManager(output_dir)
        self.dataset.set_target(target)
        self.executor = ToolExecutor(output_dir)

        # Module instances
        self.subdomain_enum  = SubdomainEnumerator(self.executor, self.scope_parser, output_dir)
        self.http_discovery  = HTTPDiscovery(self.executor, output_dir)
        self.port_scanner    = PortScanner(self.executor, output_dir)
        self.endpoint_disc   = EndpointDiscovery(self.executor, WORDLIST_DIR, output_dir)
        self.js_analyzer     = JSAnalyzer(self.executor, output_dir)
        self.api_schema      = APISchemaExtractor(self.executor, output_dir)
        self.cloud_discovery = CloudDiscovery(self.executor, WORDLIST_DIR, output_dir)
        self.screenshot_eng  = ScreenshotEngine(self.executor, output_dir, model_router)
        self.vuln_hints      = VulnHintEngine(output_dir)
        self.graph_generator = AttackSurfaceGraph(output_dir)

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────

    def _ask_permutation(self, subdomain_count: int) -> str:
        """Interactive permutation prompt — shown after Phase 3 with real count."""
        est = max(subdomain_count * 30, 500)
        console.print(f"\n[bold yellow]  ⚡ Phase 4 — Subdomain Permutation Engine[/bold yellow]")
        console.print(f"  Found [cyan]{subdomain_count}[/cyan] resolved subdomains.")
        console.print(f"  Estimated permutation DNS queries: ~{est:,}\n")
        console.print("  1. Full permutation  (dnsgen + altdns — all combinations)")
        console.print("  2. Limited           (fast/filtered set)")
        console.print("  3. Skip              (recommended for small targets)")
        choice = (console.input("\n  [bold]Run permutation?[/bold] (1-3, default=3): ").strip() or "3")
        return {"1": "full", "2": "limited", "3": "skip"}.get(choice, "skip")

    def _extract_host_urls(self, live_hosts, limit: int = 30) -> List[str]:
        """Safely extract http/https URL strings from live_hosts list."""
        urls = []
        for h in live_hosts[:limit]:
            if isinstance(h, dict):
                url = h.get("url", "")
                if url:
                    urls.append(url)
            elif isinstance(h, str):
                urls.append(h if h.startswith("http") else f"https://{h}")
        return urls

    def _get_open_port_urls(self, port_results: dict) -> List[str]:
        """
        Build http/https URLs from open port scan results.
        Used as primary input to httpx (Phase 6 per spec).
        """
        urls = []
        web_ports = {80, 443, 8080, 8443, 8000, 8008, 8888, 9090, 9443, 3000, 4000, 5000}
        for host, ports in port_results.items():
            for p in ports:
                port_num = p.get("port", 0)
                if port_num in web_ports:
                    scheme = "https" if port_num in {443, 8443, 9443} else "http"
                    url    = f"{scheme}://{host}:{port_num}" if port_num not in {80, 443} else f"{scheme}://{host}"
                    urls.append(url)
        return list(set(urls))

    # ──────────────────────────────────────────────────────────
    # Main pipeline
    # ──────────────────────────────────────────────────────────

    async def run(self) -> dict:
        banner()
        console.print(f"[bold cyan]  Target:   {self.target}[/bold cyan]")
        console.print(f"[bold cyan]  Model:    {self.model_router.name}[/bold cyan]")
        console.print(f"[bold cyan]  Output:   {self.output_dir}[/bold cyan]\n")

        # ══════════════════════════════════════════════════════
        # PHASE 1 — Scope Processing
        # ══════════════════════════════════════════════════════
        section("Phase 1 — Scope Processing")
        root_domains = self.scope_parser.get_root_domains() or [self.target]
        info(f"Scope domains: {root_domains}")
        # scope_domains.txt
        (self.output_dir / "scope_domains.txt").write_text("\n".join(root_domains))

        # ══════════════════════════════════════════════════════
        # PHASE 2 — Parallel Subdomain Discovery
        # subfinder | amass | assetfinder | chaos → subdomains_raw.txt
        # ══════════════════════════════════════════════════════
        all_subdomains = []
        for domain in root_domains:
            subs = await self.subdomain_enum.enumerate(domain)
            all_subdomains.extend(subs)

        all_subdomains = list(set(all_subdomains))
        if self.target not in all_subdomains:
            all_subdomains.append(self.target)

        self.dataset.update("subdomains", all_subdomains)
        stat("Phase 2 complete — Subdomains discovered", len(all_subdomains))

        # ══════════════════════════════════════════════════════
        # PHASE 3 — DNS Resolution
        # dnsx → resolved_subdomains.txt
        # ══════════════════════════════════════════════════════
        resolved = await self.subdomain_enum.resolve(all_subdomains)
        if self.target not in resolved:
            resolved.append(self.target)
        resolved = list(set(resolved))
        self.dataset.update("resolved_subdomains", resolved)
        stat("Phase 3 complete — Resolved subdomains", len(resolved))

        # ══════════════════════════════════════════════════════
        # PHASE 4 — Subdomain Permutation (user-prompted)
        # dnsgen + altdns → permutations.txt
        # dnsx validate → valid_permutations.txt
        # merged back into resolved list
        # ══════════════════════════════════════════════════════
        perm_mode = self.options.get("permutation_mode", "skip")
        if perm_mode == "ask":
            perm_mode = self._ask_permutation(len(resolved))

        if perm_mode not in (None, "skip"):
            resolved = await self.subdomain_enum.permutate(resolved, perm_mode)
            if self.target not in resolved:
                resolved.append(self.target)
            resolved = list(set(resolved))
            self.dataset.update("resolved_subdomains", resolved)
            stat("Phase 4 complete — Post-permutation resolved", len(resolved))
        else:
            info("Phase 4 — Permutation: skipped")

        # ══════════════════════════════════════════════════════
        # PHASE 5 — Port Scanning
        # rustscan → nmap → open_ports.txt / open_ports.json
        # ══════════════════════════════════════════════════════
        if self.options.get("port_scan", True):
            section("Phase 5 — Port Scanning")
            # Port scan takes resolved hostnames (strip to bare domains)
            scan_targets = list(set(
                h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                for h in resolved[:50]
            ))
            scan_targets = [t for t in scan_targets if t]
            port_results = await self.port_scanner.scan(scan_targets)
            self.dataset.update("open_ports", port_results)
            stat("Phase 5 complete — Open ports", sum(len(p) for p in port_results.values()))
        else:
            port_results = {}
            info("Phase 5 — Port scan: skipped")

        # ══════════════════════════════════════════════════════
        # PHASE 6 — HTTP Service Discovery
        # httpx input = open_ports.txt (or resolved if no port scan)
        # Output: live_hosts.txt / live_hosts.json
        # ══════════════════════════════════════════════════════
        section("Phase 6 — HTTP Service Discovery")
        # Per spec: httpx takes open_ports.txt as input
        if port_results:
            # Build probe list from open web ports
            port_probe = self._get_open_port_urls(port_results)
            if not port_probe:
                # Port scan found ports but none are web ports — fall back to resolved
                port_probe = resolved
            info(f"httpx probing {len(port_probe)} targets (from port scan results)")
        else:
            # No port scan — probe resolved subdomains directly
            port_probe = resolved
            info(f"httpx probing {len(port_probe)} resolved subdomains (no port data)")

        live_hosts = await self.http_discovery.discover(port_probe)
        self.dataset.update("live_hosts", live_hosts)
        stat("Phase 6 complete — Live HTTP services", len(live_hosts))

        # ══════════════════════════════════════════════════════
        # PHASE 7 — Screenshot Recon
        # gowitness + EyeWitness → screenshots/
        # AI classification: login portals, admin panels, etc.
        # ══════════════════════════════════════════════════════
        if self.options.get("screenshots", True):
            section("Phase 7 — Screenshot Recon")
            classified = await self.screenshot_eng.capture_and_classify(live_hosts)
            self.dataset.update("live_hosts", classified)
            live_hosts = classified
            stat("Phase 7 complete — Screenshots captured & classified", len(classified))
        else:
            info("Phase 7 — Screenshots: skipped")

        # ══════════════════════════════════════════════════════
        # PHASE 8 — Technology Fingerprinting
        # Already done by httpx in Phase 6 (-tech-detect flag)
        # This phase extracts + consolidates the technology data
        # ══════════════════════════════════════════════════════
        section("Phase 8 — Technology Fingerprinting")
        tech_inventory = {}
        for host in live_hosts:
            if isinstance(host, dict):
                techs = host.get("technologies", [])
                for t in techs:
                    tech_inventory[t] = tech_inventory.get(t, 0) + 1
        self.dataset.update("technologies", tech_inventory)
        stat("Phase 8 complete — Distinct technologies", len(tech_inventory))
        if tech_inventory:
            top_techs = sorted(tech_inventory.items(), key=lambda x: -x[1])[:10]
            console.print(f"  [dim]Top techs: {', '.join(t for t, _ in top_techs)}[/dim]")

        # ══════════════════════════════════════════════════════
        # PHASE 9 — JavaScript Discovery
        # katana -extension-match js → js_urls.txt
        # ══════════════════════════════════════════════════════
        host_urls = self._extract_host_urls(live_hosts, limit=25)
        if not host_urls:
            warn("No live host URLs — building from resolved list")
            host_urls = [f"https://{d}" for d in resolved[:15]]

        js_urls = await self.js_analyzer.collect_js_urls(host_urls)
        self.dataset.update("js_urls", js_urls)

        # ══════════════════════════════════════════════════════
        # PHASE 10 — JavaScript Secret Detection
        # TruffleHog + gitleaks + regex → js_secrets.json
        # ══════════════════════════════════════════════════════
        if js_urls:
            secrets = await self.js_analyzer.detect_secrets(js_urls)
            self.dataset.update("js_secrets", secrets)
        else:
            info("Phase 10 — No JS files found to scan for secrets")
            secrets = []

        # ══════════════════════════════════════════════════════
        # PHASE 11 — JavaScript Endpoint Extraction
        # xnLinkFinder + LinkFinder + regex → js_endpoints.txt
        # merged into endpoint dataset
        # ══════════════════════════════════════════════════════
        js_endpoints = await self.js_analyzer.extract_endpoints(js_urls, host_urls)
        self.dataset.update("js_endpoints", js_endpoints)

        # ══════════════════════════════════════════════════════
        # PHASE 12 — Endpoint Discovery
        # katana (crawl) + ffuf (brute) + gau + waybackurls
        # → endpoints.txt
        # ══════════════════════════════════════════════════════
        endpoints = await self.endpoint_disc.discover(host_urls)
        # Merge JS endpoints into endpoint dataset
        all_endpoints = list(set(endpoints + js_endpoints))
        self.dataset.update("endpoints", all_endpoints)
        stat("Phase 12 complete — Total endpoints", len(all_endpoints))

        # ══════════════════════════════════════════════════════
        # PHASE 13 — API Schema Extraction
        # swagger.json, openapi.json, graphql, api-docs
        # → api_schema.json
        # ══════════════════════════════════════════════════════
        api_schema_data = await self.api_schema.extract(host_urls)
        self.dataset.update("api_schema", api_schema_data)

        # ══════════════════════════════════════════════════════
        # PHASE 14 — API Discovery
        # katana (crawl) + gau + waybackurls (historical)
        # + ffuf (wordlist fuzzing) → api_endpoints.txt
        # ══════════════════════════════════════════════════════
        section("Phase 14 — API Discovery")
        api_fuzzed = await self.endpoint_disc.fuzz_api_endpoints(host_urls)
        # Merge with API-like endpoints already discovered
        api_like = [
            e for e in all_endpoints
            if any(kw in e.lower() for kw in
                   ["/api", "graphql", "swagger", "openapi", "/rest", "/v1/", "/v2/", "/v3/"])
        ]
        # Also pull in API paths from schema extraction
        schema_paths = []
        for schema in api_schema_data.get("schemas", []):
            for p in schema.get("parsed", {}).get("paths", []):
                schema_paths.append(p)

        all_apis = list(set(api_fuzzed + api_like + schema_paths))
        self.dataset.update("apis", all_apis)
        stat("Phase 14 complete — API endpoints", len(all_apis))

        # ══════════════════════════════════════════════════════
        # PHASE 15 — Cloud Asset Discovery
        # custom probes + CloudEnum + CloudBrute
        # → cloud_assets.txt / cloud_assets.json
        # ══════════════════════════════════════════════════════
        company_name = self.target.split(".")[0]
        cloud_assets = await self.cloud_discovery.discover(company_name, self.target)
        self.dataset.update("cloud_assets", cloud_assets)
        stat("Phase 15 complete — Cloud assets", len(cloud_assets))

        # ══════════════════════════════════════════════════════
        # PHASE 16 — Vulnerability Hint Detection
        # AI analyzes all collected data for vuln indicators
        # → vulnerability_hints.json
        # ══════════════════════════════════════════════════════
        hints = self.vuln_hints.analyze(self.dataset.get())
        self.dataset.update("vulnerability_hints", hints)
        stat("Phase 16 complete — Vulnerability hints", len(hints))

        # ══════════════════════════════════════════════════════
        # PHASE 17 — Dataset Storage + Attack Surface Graph
        # All files already saved per-phase
        # Graph: target → subdomains → live hosts → vuln hints → cloud
        # ══════════════════════════════════════════════════════
        section("Phase 17 — Attack Surface Graph Generation")
        graph_path = self.graph_generator.generate(self.target, self.dataset.get())
        info(f"Graph saved → {graph_path}")

        # ══════════════════════════════════════════════════════
        # AI Analysis (between 17 and 18)
        # ══════════════════════════════════════════════════════
        section("AI Analysis & Prioritisation")
        info(f"Sending recon data to {self.model_router.name}...")

        ai_input = {
            "target":            self.target,
            "subdomains_count":  len(all_subdomains),
            "resolved_count":    len(resolved),
            "live_hosts": [
                {
                    "url":      h.get("url", ""),
                    "title":    h.get("title", ""),
                    "techs":    h.get("technologies", [])[:5],
                    "category": h.get("category", ""),
                    "status":   h.get("status_code", 0),
                    "cdn":      h.get("cdn", ""),
                    "waf":      h.get("waf", ""),
                }
                for h in live_hosts[:30] if isinstance(h, dict)
            ],
            "open_ports_interesting": self.port_scanner.get_interesting_ports(
                self.dataset.get("open_ports") or {}
            )[:20],
            "cloud_assets":       cloud_assets[:20],
            "js_secrets_count":   len(secrets),
            "js_secrets_types":   list(set(s.get("type", "") for s in secrets)),
            "endpoints_count":    len(all_endpoints),
            "api_endpoints":      all_apis[:25],
            "api_schemas_found":  api_schema_data.get("total_schemas_found", 0),
            "technologies":       list(tech_inventory.keys())[:20],
            "critical_hints":     [h for h in hints if h.get("priority") == "CRITICAL"][:15],
            "high_hints":         [h for h in hints if h.get("priority") == "HIGH"][:15],
        }

        try:
            ai_analysis = self.model_router.analyze_recon_data(ai_input)
            self.dataset.update("ai_analysis", ai_analysis)
            success("AI analysis complete")
        except Exception as e:
            warn(f"AI analysis skipped: {e}")
            ai_analysis = {}

        # ══════════════════════════════════════════════════════
        # PHASE 18 — Priority Target Identification + Final Report
        # Score 1–10, rank all assets
        # Output: final_report.json, report.md, attack_surface_graph.html
        # ══════════════════════════════════════════════════════
        section("Phase 18 — Priority Target Identification & Final Report")
        final_report = self.dataset.generate_final_report(ai_analysis)

        console.print(f"\n[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]")
        console.print(f"[bold green]  📁 Output: {self.output_dir}[/bold green]")
        console.print(f"  [cyan]Phase outputs:[/cyan]")
        for fname in [
            "scope_domains.txt",
            "subdomains_raw.txt",      # Phase 2
            "resolved_subdomains.txt", # Phase 3
            "permutations.txt",        # Phase 4 (if run)
            "valid_permutations.txt",  # Phase 4 (if run)
            "open_ports.txt",          # Phase 5
            "open_ports.json",
            "live_hosts.txt",          # Phase 6
            "live_hosts.json",
            "screenshots/",            # Phase 7
            "js_urls.txt",             # Phase 9
            "js_secrets.json",         # Phase 10
            "js_secrets.txt",
            "js_endpoints.txt",        # Phase 11
            "endpoints.txt",           # Phase 12
            "api_schema.json",         # Phase 13
            "api_endpoints.txt",       # Phase 14
            "cloud_assets.json",       # Phase 15
            "cloud_assets.txt",
            "vulnerability_hints.json",# Phase 16
            "attack_surface_graph.html", # Phase 17
            "final_report.json",       # Phase 18
            "report.md",
        ]:
            path = self.output_dir / fname
            if path.exists():
                size = path.stat().st_size
                console.print(f"  [green]  ✔[/green] [dim]{fname}[/dim] [dim]({size:,} bytes)[/dim]")
        console.print(f"[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]\n")

        return final_report
