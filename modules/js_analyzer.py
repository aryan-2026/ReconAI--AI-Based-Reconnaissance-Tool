"""
ReconAI - JavaScript Analysis Engine

Phase 9  — JavaScript Discovery (katana -extension-match js)
Phase 10 — Secret Detection (TruffleHog + gitleaks + regex patterns)
Phase 11 — Endpoint Extraction (xnLinkFinder + LinkFinder + regex)
"""
import asyncio
import re
import json
import hashlib
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Tuple
from tools.executor import ToolExecutor
from utils.logger import section, info, success, warn, error

# Suppress httpx noise from JS downloads
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class JSAnalyzer:
    """
    Phase 9  — JS Discovery:
        katana -extension-match js → js_urls.txt

    Phase 10 — Secret Detection:
        TruffleHog (http mode) → js_secrets.json
        gitleaks detect         → merged into js_secrets.json
        regex patterns          → merged into js_secrets.json

    Phase 11 — Endpoint Extraction:
        xnLinkFinder            → js_endpoints.txt
        LinkFinder              → merged into js_endpoints.txt
        regex patterns          → merged into js_endpoints.txt
    """

    SECRET_PATTERNS = {
        "aws_access_key":      r"AKIA[0-9A-Z]{16}",
        "aws_secret_key":      r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "google_api_key":      r"AIza[0-9A-Za-z\-_]{35}",
        "jwt_token":           r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "github_token":        r"gh[pousr]_[0-9a-zA-Z]{36}",
        "stripe_live_key":     r"sk_live_[0-9a-zA-Z]{24}",
        "stripe_pub_key":      r"pk_live_[0-9a-zA-Z]{24}",
        "slack_token":         r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
        "private_key_block":   r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----",
        "sendgrid_key":        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "mailgun_key":         r"key-[0-9a-zA-Z]{32}",
        "twilio_sid":          r"AC[0-9a-f]{32}",
        "heroku_api_key":      r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "password_in_var":     r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "basic_auth_url":      r"https?://[^:]+:[^@]+@[^/]+",
        "firebase_url":        r"https://[a-z0-9-]+\.firebaseio\.com",
        "generic_secret":      r"(?i)(secret|token|key|password)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
        "oauth_client_secret": r"(?i)client.?secret.{0,10}['\"][a-zA-Z0-9_\-]{16,}['\"]",
        "discord_token":       r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
        "npm_token":           r"npm_[a-zA-Z0-9]{36}",
    }

    ENDPOINT_PATTERNS = [
        r"""['"` ](/[a-zA-Z0-9_\-/.]+)['"` ]""",
        r"""url\s*[:=]\s*['"` ]([^'"` \n]{5,150})['"` ]""",
        r"""fetch\(['"` ]([^'"` ]+)['"` ]""",
        r"""axios\.[a-z]+\(['"` ]([^'"` ]+)['"` ]""",
        r"""XMLHttpRequest.*open\(['\"](GET|POST|PUT|DELETE|PATCH)['\"],\s*['\"]([^'"]+)['\"]""",
        r"""(?:href|action|src|endpoint|baseURL|basePath)\s*=\s*['"` ]([^'"` ]{5,150})['"` ]""",
        r"""api(?:Url|Base|Endpoint|Path|Host)\s*[=:]\s*['"` ]([^'"` ]+)['"` ]""",
        r"""\$\.(?:get|post|ajax|put|delete)\(['"]([^'"]+)['"]""",
    ]

    def __init__(self, executor: ToolExecutor, output_dir: Path):
        self.executor   = executor
        self.output_dir = output_dir
        self.js_dir     = output_dir / "js_files"
        self.js_dir.mkdir(parents=True, exist_ok=True)
        self._katana_flags = None   # cached after first detect

    # ──────────────────────────────────────────────────────────
    # Phase 9 — JavaScript Discovery
    # ──────────────────────────────────────────────────────────

    async def collect_js_urls(self, live_hosts: List[str]) -> List[str]:
        """
        Phase 9: Discover all JS file URLs using katana.
        Saves: js_urls.txt
        """
        section("Phase 9 — JavaScript Discovery")
        js_urls = []

        if self.executor.check_tool("katana"):
            jscrawl_flag, noscope_flag = self._get_katana_flags()

            tasks = []
            for host in live_hosts[:20]:
                if not host.startswith("http"):
                    host = f"https://{host}"
                tasks.append(self.executor.run_async(
                    [
                        "katana", "-u", host,
                        "-silent",
                        "-depth", "3",
                        jscrawl_flag,
                        "-extension-match", "js",
                        noscope_flag,
                        "-timeout", "30",
                    ],
                    timeout=180
                ))

            results = await asyncio.gather(*tasks)
            for output in results:
                if output:
                    for url in output.splitlines():
                        url = url.strip()
                        if url and (url.endswith(".js") or ".js?" in url or ".js#" in url):
                            js_urls.append(url)
        else:
            warn("katana not found — JS URLs will be extracted from crawled endpoints only")

        js_urls = list(set(js_urls))
        self.executor.save_results("js_urls.txt", js_urls)
        success(f"Phase 9 complete: {len(js_urls)} JS file URLs found")
        return js_urls

    # ──────────────────────────────────────────────────────────
    # Phase 10 — Secret Detection
    # ──────────────────────────────────────────────────────────

    async def detect_secrets(self, js_urls: List[str]) -> List[Dict]:
        """
        Phase 10: Hybrid secret detection:
          1. TruffleHog (HTTP scan mode)
          2. gitleaks detect (on downloaded JS files)
          3. Regex patterns (always runs as fallback)
        Saves: js_secrets.json, js_secrets.txt
        """
        section("Phase 10 — JavaScript Secret Detection")

        all_secrets = []

        if not js_urls:
            warn("No JS URLs — skipping secret detection")
            return []

        # Step 1: Download all JS files
        info(f"Downloading {min(len(js_urls), 100)} JS files...")
        downloaded = await self._download_js_files(js_urls[:100])

        # Step 2: TruffleHog
        trufflehog_results = await self._run_trufflehog(js_urls[:50])
        all_secrets.extend(trufflehog_results)

        # Step 3: gitleaks
        gitleaks_results = await self._run_gitleaks(downloaded)
        all_secrets.extend(gitleaks_results)

        # Step 4: Regex patterns (always runs)
        regex_results = await self._regex_scan_all(downloaded)
        all_secrets.extend(regex_results)

        # Deduplicate
        all_secrets = self._deduplicate_secrets(all_secrets)
        self._save_secrets(all_secrets)
        success(f"Phase 10 complete: {len(all_secrets)} secrets detected")
        return all_secrets

    async def _download_js_files(self, js_urls: List[str]) -> List[Path]:
        """Download JS files and return list of local paths."""
        import httpx as httpx_lib
        downloaded = []

        async def fetch_one(url: str):
            try:
                async with httpx_lib.AsyncClient(
                    verify=False, timeout=15,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 ReconAI/2.0"}
                ) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200 and resp.text:
                        content    = self._beautify(resp.text, url)
                        file_hash  = hashlib.md5(url.encode()).hexdigest()[:10]
                        js_file    = self.js_dir / f"{file_hash}.js"
                        js_file.write_text(content, encoding="utf-8", errors="ignore")
                        return js_file
            except Exception:
                pass
            return None

        results = await asyncio.gather(*[fetch_one(u) for u in js_urls])
        downloaded = [r for r in results if r is not None]
        info(f"Downloaded {len(downloaded)} JS files")
        return downloaded

    async def _run_trufflehog(self, js_urls: List[str]) -> List[Dict]:
        """Run TruffleHog in HTTP mode against discovered JS URLs."""
        if not self.executor.check_tool("trufflehog"):
            warn("TruffleHog not found — skipping (install: go install github.com/trufflesecurity/trufflehog/v3@latest)")
            return []

        info(f"Running TruffleHog against {len(js_urls)} JS URLs...")
        results = []

        # TruffleHog v3: trufflehog filesystem ./js_files --json --no-verification
        output = await self.executor.run_async(
            [
                "trufflehog", "filesystem",
                str(self.js_dir),
                "--json",
                "--no-verification",
                "--only-verified=false",
            ],
            timeout=300
        )

        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    # TruffleHog v3 JSON format
                    detector = obj.get("DetectorName", obj.get("detector_name", "unknown"))
                    raw      = obj.get("Raw", obj.get("raw", ""))
                    source   = obj.get("SourceMetadata", {})
                    file_ref = source.get("Data", {}).get("Filesystem", {}).get("file", "")
                    results.append({
                        "type":       f"trufflehog_{detector}",
                        "value":      str(raw)[:100],
                        "source_url": file_ref,
                        "tool":       "trufflehog",
                    })
                except Exception:
                    pass

        if results:
            success(f"TruffleHog: {len(results)} secrets found")
        else:
            info("TruffleHog: no secrets detected")
        return results

    async def _run_gitleaks(self, downloaded_files: List[Path]) -> List[Dict]:
        """Run gitleaks detect against downloaded JS files directory."""
        if not self.executor.check_tool("gitleaks"):
            warn("gitleaks not found — skipping (install: go install github.com/gitleaks/gitleaks/v8@latest)")
            return []

        if not downloaded_files:
            return []

        info("Running gitleaks against downloaded JS files...")
        gitleaks_out = self.output_dir / "gitleaks_report.json"

        output = await self.executor.run_async(
            [
                "gitleaks", "detect",
                "--source", str(self.js_dir),
                "--report-format", "json",
                "--report-path", str(gitleaks_out),
                "--no-git",
                "--exit-code", "0",   # don't fail on findings
                "--redact",
            ],
            timeout=180
        )

        results = []
        if gitleaks_out.exists() and gitleaks_out.stat().st_size > 2:
            try:
                findings = json.loads(gitleaks_out.read_text())
                if isinstance(findings, list):
                    for f in findings:
                        results.append({
                            "type":       f"gitleaks_{f.get('RuleID', 'unknown')}",
                            "value":      f.get("Secret", f.get("Match", ""))[:100],
                            "source_url": f.get("File", ""),
                            "tool":       "gitleaks",
                            "line":       f.get("StartLine", 0),
                        })
            except Exception:
                pass

        if results:
            success(f"gitleaks: {len(results)} secrets found")
        else:
            info("gitleaks: no secrets detected")
        return results

    async def _regex_scan_all(self, downloaded_files: List[Path]) -> List[Dict]:
        """Regex-based secret scanning across all downloaded JS files."""
        info(f"Regex secret scan across {len(downloaded_files)} JS files...")
        secrets = []
        for js_file in downloaded_files:
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                file_secrets = self._extract_secrets(content, str(js_file))
                secrets.extend(file_secrets)
            except Exception:
                pass
        return secrets

    def _extract_secrets(self, content: str, source_url: str) -> List[Dict]:
        secrets = []
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                value = match.group(0)
                if len(value) < 8 or value.count("x") > len(value) * 0.5:
                    continue
                secrets.append({
                    "type":       secret_type,
                    "value":      value[:100],
                    "source_url": source_url,
                    "tool":       "regex",
                    "context":    content[max(0, match.start()-30):match.end()+30].strip()
                })
        return secrets

    # ──────────────────────────────────────────────────────────
    # Phase 11 — Endpoint Extraction
    # ──────────────────────────────────────────────────────────

    async def extract_endpoints(self, js_urls: List[str], live_hosts: List[str]) -> List[str]:
        """
        Phase 11: Multi-tool endpoint extraction:
          1. xnLinkFinder (best for JS endpoint extraction)
          2. LinkFinder    (classic, regex-based)
          3. Regex patterns (always runs as fallback)
        Saves: js_endpoints.txt
        """
        section("Phase 11 — JavaScript Endpoint Extraction")

        all_endpoints = []

        if not js_urls and not self.js_dir.exists():
            warn("No JS files available for endpoint extraction")
            return []

        # Method 1: xnLinkFinder
        xn_results = await self._run_xnlinkfinder(live_hosts)
        all_endpoints.extend(xn_results)

        # Method 2: LinkFinder
        lf_results = await self._run_linkfinder(js_urls[:30])
        all_endpoints.extend(lf_results)

        # Method 3: Regex on downloaded files
        downloaded = list(self.js_dir.glob("*.js"))
        for js_file in downloaded:
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                endpoints = self._extract_endpoints_regex(content)
                all_endpoints.extend(endpoints)
            except Exception:
                pass

        all_endpoints = list(set(all_endpoints))
        self.executor.save_results("js_endpoints.txt", all_endpoints)
        success(f"Phase 11 complete: {len(all_endpoints)} endpoints extracted from JS")
        return all_endpoints

    async def _run_xnlinkfinder(self, live_hosts: List[str]) -> List[str]:
        """xnLinkFinder: crawls live hosts to find all links/endpoints in JS."""
        if not self.executor.check_tool("xnLinkFinder") and not self.executor.check_tool("xnlinkfinder"):
            warn("xnLinkFinder not found — skipping (pip install xnLinkFinder)")
            return []

        tool = "xnLinkFinder" if self.executor.check_tool("xnLinkFinder") else "xnlinkfinder"
        endpoints = []
        xnlf_out = self.output_dir / "xnlinkfinder_output.txt"

        for host in live_hosts[:10]:
            if not host.startswith("http"):
                host = f"https://{host}"

            output = await self.executor.run_async(
                [
                    tool,
                    "-i", host,
                    "-sf", host,    # scope filter
                    "-d", "3",      # depth
                    "-o", str(xnlf_out),
                    "-op", str(self.output_dir / "xnlf_parameters.txt"),
                ],
                timeout=180
            )

            if xnlf_out.exists() and xnlf_out.stat().st_size > 0:
                for line in xnlf_out.read_text().splitlines():
                    line = line.strip()
                    if line and (line.startswith("/") or line.startswith("http")):
                        endpoints.append(line)

        if endpoints:
            info(f"xnLinkFinder: {len(endpoints)} endpoints")
        return list(set(endpoints))

    async def _run_linkfinder(self, js_urls: List[str]) -> List[str]:
        """LinkFinder: classic Python tool for extracting endpoints from JS files."""
        if not self.executor.check_tool("linkfinder") and not self.executor.check_tool("LinkFinder"):
            warn("LinkFinder not found — skipping (pip install linkfinder OR python3 LinkFinder.py)")
            return []

        tool = "linkfinder" if self.executor.check_tool("linkfinder") else "LinkFinder"
        endpoints = []
        lf_out = self.output_dir / "linkfinder_output.txt"

        for js_url in js_urls[:20]:
            output = await self.executor.run_async(
                [
                    tool,
                    "-i", js_url,
                    "-o", "cli",
                ],
                timeout=60
            )
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    if line and (line.startswith("/") or line.startswith("http")):
                        endpoints.append(line)

        if endpoints:
            info(f"LinkFinder: {len(endpoints)} endpoints")
        return list(set(endpoints))

    def _extract_endpoints_regex(self, content: str) -> List[str]:
        """Regex endpoint extraction — always runs as baseline."""
        endpoints = []
        for pattern in self.ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                groups = match.groups()
                path   = groups[-1] if groups else match.group(0)
                if not path or len(path) < 3:
                    continue
                if any(skip in path for skip in [
                    ".png", ".jpg", ".gif", ".svg", ".css", ".woff",
                    "{{", "${", "example.com", "localhost", "127.0.0.1",
                ]):
                    continue
                if path.startswith("/") or path.startswith("http"):
                    endpoints.append(path)
        return list(set(endpoints))

    # ──────────────────────────────────────────────────────────
    # Combined entry point (backwards compat with controller)
    # ──────────────────────────────────────────────────────────

    async def analyze(self, js_urls: List[str], live_hosts: List[str] = None) -> Tuple[List[Dict], List[str]]:
        """
        Run Phase 10 (secrets) + Phase 11 (endpoints) sequentially.
        Returns (secrets, endpoints).
        """
        secrets   = await self.detect_secrets(js_urls)
        endpoints = await self.extract_endpoints(js_urls, live_hosts or [])
        return secrets, endpoints

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────

    def _beautify(self, js_content: str, url: str) -> str:
        try:
            import jsbeautifier
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            return jsbeautifier.beautify(js_content, opts)
        except Exception:
            return js_content

    def _get_katana_flags(self) -> Tuple[str, str]:
        if self._katana_flags:
            return self._katana_flags
        try:
            result = subprocess.run(
                ["katana", "-version"], capture_output=True, text=True, timeout=5
            )
            ver_out = result.stdout + result.stderr
            if "2." in ver_out:
                self._katana_flags = ("-jc", "-nos")
            else:
                self._katana_flags = ("-js-crawl", "-no-scope-check")
        except Exception:
            self._katana_flags = ("-js-crawl", "-no-scope-check")
        return self._katana_flags

    def _deduplicate_secrets(self, secrets: List[Dict]) -> List[Dict]:
        seen, unique = set(), []
        for s in secrets:
            key = s.get("value", "")[:50]
            if key and key not in seen:
                seen.add(key)
                unique.append(s)
        return unique

    def _save_secrets(self, secrets: List[Dict]):
        json_path = self.output_dir / "js_secrets.json"
        json_path.write_text(json.dumps(secrets, indent=2))
        lines = [
            f"[{s['tool'].upper()}][{s['type']}] {s['value'][:80]} | {s['source_url']}"
            for s in secrets
        ]
        self.executor.save_results("js_secrets.txt", lines)
        if secrets:
            from utils.logger import console
            console.print(f"\n[bold red]  🔑 SECRETS FOUND: {len(secrets)} credentials detected![/bold red]")
            for s in secrets[:5]:
                console.print(f"  [red]  • [{s['tool'].upper()}][{s['type']}] {s['value'][:70]}[/red]")
