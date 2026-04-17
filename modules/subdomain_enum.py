"""
ReconAI - Subdomain Enumeration Engine
Phase 2: Parallel passive discovery — subfinder, amass, assetfinder, chaos
Phase 3: DNS resolution via dnsx
Phase 4: Permutation via dnsgen + altdns, then re-resolve
"""
import asyncio
import subprocess
from pathlib import Path
from typing import List
from tools.executor import ToolExecutor
from core.scope_parser import ScopeParser
from utils.logger import log, section, info, success, warn


class SubdomainEnumerator:
    """
    Phase 2 — Parallel Subdomain Discovery:
      subfinder | amass | assetfinder | chaos  → subdomains_raw.txt

    Phase 3 — DNS Resolution:
      dnsx → resolved_subdomains.txt

    Phase 4 — Subdomain Permutation (optional, user-prompted):
      dnsgen | altdns → permutations.txt → dnsx → valid_permutations.txt
      merged back into resolved list
    """

    def __init__(self, executor: ToolExecutor, scope: ScopeParser, output_dir: Path):
        self.executor   = executor
        self.scope      = scope
        self.output_dir = output_dir

    # ──────────────────────────────────────────────────────────
    # Phase 2 — Parallel Subdomain Discovery
    # ──────────────────────────────────────────────────────────

    async def enumerate(self, domain: str) -> List[str]:
        """
        Launch subfinder, amass, assetfinder, and chaos in parallel.
        Merge, deduplicate, scope-filter, then return.
        """
        section(f"Subdomain Enumeration → {domain}")

        tasks = []

        # subfinder
        if self.executor.check_tool("subfinder"):
            tasks.append({
                "name":    "subfinder",
                "cmd":     ["subfinder", "-d", domain, "-silent", "-all"],
                "timeout": 300
            })

        # amass (passive only — fast)
        if self.executor.check_tool("amass"):
            tasks.append({
                "name":    "amass",
                "cmd":     ["amass", "enum", "-passive", "-d", domain, "-silent"],
                "timeout": 600
            })

        # assetfinder
        if self.executor.check_tool("assetfinder"):
            tasks.append({
                "name":    "assetfinder",
                "cmd":     ["assetfinder", "--subs-only", domain],
                "timeout": 180
            })

        # chaos (ProjectDiscovery public dataset)
        if self.executor.check_tool("chaos"):
            tasks.append({
                "name":    "chaos",
                "cmd":     ["chaos", "-d", domain, "-silent", "-key",
                            self._chaos_key()],
                "timeout": 120
            })

        # Always seed the bare root domain
        all_subs = [domain]

        if tasks:
            results = await self.executor.run_parallel(tasks)
            for tool_name, output in results.items():
                if output:
                    subs = self._parse_subdomains(output, domain)
                    info(f"{tool_name}: {len(subs)} subdomains")
                    all_subs.extend(subs)
        else:
            warn("No subdomain tools available — only root domain will be scanned")

        all_subs = list(set(all_subs))
        all_subs = self.scope.filter_domains(all_subs)
        if domain not in all_subs:
            all_subs.append(domain)

        self.executor.save_results("subdomains_raw.txt", all_subs)
        success(f"Subdomain discovery: {len(all_subs)} unique subdomains")
        return all_subs

    def _chaos_key(self) -> str:
        import os
        return os.getenv("CHAOS_API_KEY", "")

    # ──────────────────────────────────────────────────────────
    # Phase 3 — DNS Resolution
    # ──────────────────────────────────────────────────────────

    async def resolve(self, subdomains: List[str]) -> List[str]:
        """
        Resolve subdomains with dnsx.
        Output: resolved_subdomains.txt
        Fallback: return original list unchanged if dnsx unavailable.
        """
        section("DNS Resolution Engine")

        if not subdomains:
            warn("No subdomains to resolve")
            return []

        if not self.executor.check_tool("dnsx"):
            warn("dnsx not available — using unresolved subdomain list")
            self.executor.save_results("resolved_subdomains.txt", subdomains)
            return subdomains

        subs_file = self.output_dir / "all_subdomains.txt"
        subs_file.write_text("\n".join(subdomains))
        info(f"Resolving {len(subdomains)} candidates with dnsx...")

        output = await self.executor.run_async(
            [
                "dnsx",
                "-l", str(subs_file),
                "-silent",
                "-resp",
                "-a", "-aaaa", "-cname",
                "-t", "100",
                "-retry", "2"
            ],
            timeout=600
        )

        if not output:
            warn("dnsx returned no results — using full subdomain list as resolved")
            self.executor.save_results("resolved_subdomains.txt", subdomains)
            return subdomains

        # dnsx output format: "sub.example.com [A] 1.2.3.4"
        resolved = []
        for line in output.splitlines():
            parts = line.strip().split()
            if parts:
                host = parts[0].lower().rstrip(".")
                if host:
                    resolved.append(host)

        resolved = self.scope.filter_domains(resolved)
        if not resolved:
            warn("dnsx resolved 0 hosts — falling back to full list")
            resolved = subdomains

        self.executor.save_results("resolved_subdomains.txt", resolved)
        success(f"DNS resolution: {len(resolved)} live subdomains")
        return resolved

    # ──────────────────────────────────────────────────────────
    # Phase 4 — Subdomain Permutation (dnsgen + altdns)
    # ──────────────────────────────────────────────────────────

    async def permutate(self, subdomains: List[str], mode: str = "limited") -> List[str]:
        """
        Generate permutations using dnsgen AND altdns in parallel,
        merge results, then re-resolve with dnsx.

        Output files:
          permutations.txt       — all generated permutation candidates
          valid_permutations.txt — those that resolve
        """
        section("Subdomain Permutation Engine")

        subs_file = self.output_dir / "subdomains_for_perm.txt"
        subs_file.write_text("\n".join(subdomains))

        permutations = []

        # ── dnsgen ────────────────────────────────────────────
        if self.executor.check_tool("dnsgen"):
            extra_flags = ["-f"] if mode == "limited" else []
            dnsgen_out  = ""

            # Method 1: file argument (older dnsgen)
            try:
                proc = subprocess.run(
                    ["dnsgen", str(subs_file)] + extra_flags,
                    capture_output=True, text=True, timeout=180
                )
                dnsgen_out = proc.stdout.strip()
            except subprocess.TimeoutExpired:
                warn("dnsgen timed out on file-arg — trying stdin mode")
            except Exception as e:
                warn(f"dnsgen file-arg failed: {e}")

            # Method 2: stdin pipe (newer dnsgen)
            if not dnsgen_out:
                try:
                    proc = subprocess.run(
                        ["dnsgen", "-"] + extra_flags,
                        input="\n".join(subdomains),
                        capture_output=True, text=True, timeout=180
                    )
                    dnsgen_out = proc.stdout.strip()
                except Exception as e:
                    warn(f"dnsgen stdin mode failed: {e}")

            if dnsgen_out:
                dnsgen_perms = [l.strip().lower() for l in dnsgen_out.splitlines() if l.strip()]
                info(f"dnsgen: {len(dnsgen_perms)} permutation candidates")
                permutations.extend(dnsgen_perms)
            else:
                warn("dnsgen produced no output")
        else:
            warn("dnsgen not found — skipping dnsgen permutation")

        # ── altdns ────────────────────────────────────────────
        if self.executor.check_tool("altdns"):
            altdns_out_file = self.output_dir / "permutations_raw.txt"
            wordlist        = self._get_altdns_wordlist()
            try:
                proc = subprocess.run(
                    [
                        "altdns",
                        "-i", str(subs_file),
                        "-o", str(altdns_out_file),
                        "-w", str(wordlist)
                    ],
                    capture_output=True, text=True, timeout=300
                )
                if altdns_out_file.exists() and altdns_out_file.stat().st_size > 0:
                    altdns_perms = [
                        l.strip().lower()
                        for l in altdns_out_file.read_text().splitlines()
                        if l.strip()
                    ]
                    info(f"altdns: {len(altdns_perms)} permutation candidates")
                    permutations.extend(altdns_perms)
                else:
                    warn("altdns produced no output")
            except subprocess.TimeoutExpired:
                warn("altdns timed out")
            except Exception as e:
                warn(f"altdns failed: {e}")
        else:
            warn("altdns not found — skipping altdns permutation")

        if not permutations:
            warn("No permutations generated — resolving original list only")
            return await self.resolve(subdomains)

        # Merge: original + all permutations
        all_candidates = list(set(subdomains + permutations))

        # Save permutations.txt (pre-validation)
        perm_file = self.output_dir / "permutations.txt"
        perm_file.write_text("\n".join(all_candidates))
        info(f"Total permutation candidates: {len(all_candidates)}")

        # Re-resolve with dnsx → valid_permutations.txt
        valid = await self._resolve_permutations(all_candidates)
        return valid

    async def _resolve_permutations(self, candidates: List[str]) -> List[str]:
        """
        Resolve permutation candidates with dnsx.
        Saves valid_permutations.txt then merges into resolved_subdomains.txt.
        """
        if not self.executor.check_tool("dnsx"):
            warn("dnsx not available — returning all candidates unvalidated")
            self.executor.save_results("valid_permutations.txt", candidates)
            return candidates

        cand_file = self.output_dir / "permutations.txt"
        cand_file.write_text("\n".join(candidates))
        info(f"Validating {len(candidates)} permutations with dnsx...")

        output = await self.executor.run_async(
            [
                "dnsx",
                "-l", str(cand_file),
                "-silent",
                "-resp",
                "-a",
                "-t", "200",
                "-retry", "1"
            ],
            timeout=900
        )

        valid = []
        if output:
            for line in output.splitlines():
                parts = line.strip().split()
                if parts:
                    host = parts[0].lower().rstrip(".")
                    if host:
                        valid.append(host)

        valid = self.scope.filter_domains(valid)
        if not valid:
            warn("Permutation resolution: 0 valid — returning original resolved list")
            existing = self.executor.load_results("resolved_subdomains.txt")
            return existing or candidates

        self.executor.save_results("valid_permutations.txt", valid)
        success(f"Permutation validation: {len(valid)} valid subdomains")

        # Merge into resolved_subdomains.txt
        existing = self.executor.load_results("resolved_subdomains.txt")
        merged   = list(set(existing + valid))
        self.executor.save_results("resolved_subdomains.txt", merged)
        return merged

    def _get_altdns_wordlist(self) -> Path:
        """Return altdns mutation wordlist — use bundled one or create minimal fallback."""
        candidates = [
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
            Path("/usr/share/wordlists/dns/subdomains-top1million-5000.txt"),
            self.output_dir.parent.parent / "wordlists" / "permutations" / "words.txt",
        ]
        for p in candidates:
            if p.exists():
                return p
        # Minimal fallback
        fallback = self.output_dir / "altdns_words.txt"
        if not fallback.exists():
            fallback.write_text("\n".join([
                "dev", "api", "staging", "prod", "test", "admin", "app",
                "beta", "new", "old", "v1", "v2", "v3", "internal",
                "portal", "dashboard", "secure", "vpn", "mail", "smtp",
                "ftp", "ssh", "uat", "qa", "demo", "cdn", "static",
                "assets", "media", "upload", "files", "backup", "db",
                "database", "shop", "store", "pay", "payment", "auth",
                "login", "sso", "oauth", "id", "accounts", "user",
            ]))
        return fallback

    def _parse_subdomains(self, output: str, domain: str) -> List[str]:
        """Parse subdomain tool output — one subdomain per line."""
        subs = []
        for line in output.splitlines():
            host = line.strip().lower().rstrip(".")
            if not host:
                continue
            # Only accept subdomains of the target domain
            if host == domain or host.endswith("." + domain):
                subs.append(host)
        return list(set(subs))
