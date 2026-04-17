"""
ReconAI - Endpoint Discovery Engine
Discovers hidden endpoints via brute force, crawling, and historical data.
"""
import asyncio
import json
from pathlib import Path
from typing import List, Dict
from tools.executor import ToolExecutor
from utils.logger import section, info, success, warn, stat


class EndpointDiscovery:
    """
    Multi-method endpoint discovery:
    1. Directory brute force (ffuf)
    2. Active crawling (katana)
    3. Historical URLs (gau + waybackurls)
    """

    def __init__(self, executor: ToolExecutor, wordlist_dir: Path, output_dir: Path):
        self.executor     = executor
        self.wordlist_dir = wordlist_dir
        self.output_dir   = output_dir

    async def discover(self, live_hosts: List[str]) -> List[str]:
        section("Endpoint Discovery Engine")

        if not live_hosts:
            warn("No live hosts passed to endpoint discovery — nothing to scan")
            return []

        all_endpoints = []
        tasks = []

        for host in live_hosts[:20]:
            # Normalise: ensure we have a URL (not bare domain)
            if not host.startswith("http"):
                host = f"https://{host}"
            tasks.append(self._discover_host(host))

        results = await asyncio.gather(*tasks)
        for endpoints in results:
            all_endpoints.extend(endpoints)

        all_endpoints = list(set(all_endpoints))
        self.executor.save_results("endpoints.txt", all_endpoints)
        success(f"Total unique endpoints discovered: {len(all_endpoints)}")
        return all_endpoints

    async def _discover_host(self, host_url: str) -> List[str]:
        """Run all discovery methods against a single host."""
        endpoints = []

        # Historical URLs (fastest, passive)
        hist = await asyncio.gather(
            self._gau(host_url),
            self._waybackurls(host_url)
        )
        for result in hist:
            endpoints.extend(result)

        # Active crawl
        crawled = await self._katana(host_url)
        endpoints.extend(crawled)

        # Directory brute force (only on interesting targets)
        if self._is_interesting_target(host_url):
            fuzzed = await self._ffuf_dirs(host_url)
            endpoints.extend(fuzzed)

        return list(set(endpoints))

    async def _gau(self, host: str) -> List[str]:
        """Get All URLs — fetches historical URLs from multiple archive sources."""
        if not self.executor.check_tool("gau"):
            return []

        domain = host.replace("https://", "").replace("http://", "").split("/")[0]

        import subprocess
        try:
            result = subprocess.run(["gau", "--help"], capture_output=True, text=True, timeout=5)
            help_out = result.stdout + result.stderr
        except Exception:
            help_out = ""

        # gau v2 uses --threads; some builds use -t — detect which is available
        threads_flag = "--threads" if "--threads" in help_out else "-t"

        output = await self.executor.run_async(
            ["gau", domain, "--subs", threads_flag, "5"],
            timeout=120
        )
        urls = self._parse_urls(output or "")
        info(f"gau [{domain}]: {len(urls)} historical URLs")
        return urls

    async def _waybackurls(self, host: str) -> List[str]:
        """Fetch URLs from Wayback Machine."""
        if not self.executor.check_tool("waybackurls"):
            return []

        domain = host.replace("https://", "").replace("http://", "").split("/")[0]
        output = await self.executor.run_async(
            ["waybackurls", domain],
            timeout=120
        )
        urls = self._parse_urls(output or "")
        info(f"waybackurls [{domain}]: {len(urls)} URLs")
        return urls

    async def _katana(self, host: str) -> List[str]:
        """Active web crawler with version-aware flags."""
        if not self.executor.check_tool("katana"):
            return []

        import subprocess
        # Detect katana version to pick correct flags
        try:
            result = subprocess.run(["katana", "-version"], capture_output=True, text=True, timeout=5)
            version_out = result.stdout + result.stderr
        except Exception:
            version_out = ""

        # Newer katana uses -jc (js-crawl) and -nos (no-scope); older used full names
        use_short = "-jc" in version_out or "2." in version_out
        jscrawl_flag = "-jc" if use_short else "-js-crawl"
        noscope_flag = "-nos" if use_short else "-no-scope-check"

        output = await self.executor.run_async(
            [
                "katana",
                "-u", host,
                "-silent",
                "-depth", "3",
                jscrawl_flag,
                noscope_flag,
                "-timeout", "30",
                "-c", "10"
            ],
            timeout=180
        )
        urls = self._parse_urls(output or "")
        info(f"katana [{host}]: {len(urls)} crawled URLs")
        return urls

    async def _ffuf_dirs(self, host: str) -> List[str]:
        """Directory brute force using ffuf."""
        if not self.executor.check_tool("ffuf"):
            return []

        wordlist = self._get_wordlist("directories")
        if not wordlist:
            return []

        output_file = self.output_dir / f"ffuf_{host.replace('://', '_').replace('/', '_')}.json"

        await self.executor.run_async(
            [
                "ffuf",
                "-u", f"{host}/FUZZ",
                "-w", str(wordlist),
                "-ac",
                "-t", "50",
                "-rate", "150",
                "-o", str(output_file),
                "-of", "json",
                "-timeout", "10",
                "-mc", "200,201,301,302,403,500"
            ],
            timeout=300
        )

        if output_file.exists():
            try:
                data = json.loads(output_file.read_text())
                results = data.get("results", [])
                urls = [r["url"] for r in results if r.get("url")]
                info(f"ffuf [{host}]: {len(urls)} endpoints")
                return urls
            except Exception:
                return []
        return []

    def _get_wordlist(self, category: str) -> Path:
        """Find the best available wordlist for a category."""
        wl_dir = self.wordlist_dir / category
        wl_dir.mkdir(parents=True, exist_ok=True)

        # Look for common wordlist filenames
        candidates = ["raft-medium-directories.txt", "common.txt", "directories.txt", "wordlist.txt"]
        for name in candidates:
            path = wl_dir / name
            if path.exists():
                return path

        # Check SecLists common locations
        seclists_paths = [
            Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
            Path("/usr/share/wordlists/dirb/common.txt"),
            Path("/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt")
        ]
        for path in seclists_paths:
            if path.exists():
                return path

        # Create minimal fallback wordlist
        fallback = wl_dir / "common.txt"
        if not fallback.exists():
            fallback.write_text("\n".join([
                "admin", "api", "login", "dashboard", "config", "backup",
                "upload", "files", "static", "assets", "js", "css", "img",
                "images", "v1", "v2", "v3", "graphql", "swagger", "docs",
                "test", "dev", "staging", "old", "new", ".git", ".env",
                "robots.txt", "sitemap.xml", "wp-admin", "wp-login.php"
            ]))
        return fallback

    def _parse_urls(self, raw: str) -> List[str]:
        """Parse newline-separated URLs from tool output."""
        urls = []
        for line in raw.splitlines():
            line = line.strip()
            if line and (line.startswith("http://") or line.startswith("https://")):
                # Normalize URL
                urls.append(line.split("?")[0])  # strip params for dedup
        return list(set(urls))

    def _is_interesting_target(self, host: str) -> bool:
        """Determine if a host warrants active directory brute force."""
        keywords = ["api", "admin", "portal", "dashboard", "manage", "app", "dev", "staging"]
        host_lower = host.lower()
        return any(kw in host_lower for kw in keywords)

    async def fuzz_api_endpoints(self, live_hosts: List[str]) -> List[str]:
        """Specifically fuzz for API endpoints."""
        section("API Endpoint Discovery via Fuzzing")

        if not self.executor.check_tool("ffuf"):
            warn("ffuf not available for API fuzzing")
            return []

        wordlist = self._get_api_wordlist()
        api_endpoints = []

        for host in live_hosts[:10]:
            output_file = self.output_dir / f"api_fuzz_{host.replace('://', '_').replace('/', '_')}.json"

            await self.executor.run_async(
                [
                    "ffuf",
                    "-u", f"{host}/FUZZ",
                    "-w", str(wordlist),
                    "-ac", "-t", "30", "-rate", "100",
                    "-o", str(output_file), "-of", "json",
                    "-timeout", "10",
                    "-mc", "200,201,204,301,302,401,403"
                ],
                timeout=180
            )

            if output_file.exists():
                try:
                    data = json.loads(output_file.read_text())
                    for r in data.get("results", []):
                        if r.get("url"):
                            api_endpoints.append(r["url"])
                except Exception:
                    pass

        self.executor.save_results("api_endpoints.txt", api_endpoints)
        success(f"API fuzzing found: {len(api_endpoints)} endpoints")
        return api_endpoints

    def _get_api_wordlist(self) -> Path:
        """Get or create API-specific wordlist."""
        api_wl = self.wordlist_dir / "api" / "api_paths.txt"
        api_wl.parent.mkdir(parents=True, exist_ok=True)

        if not api_wl.exists():
            api_wl.write_text("\n".join([
                "api", "api/v1", "api/v2", "api/v3", "api/v4",
                "graphql", "graphiql", "swagger", "swagger.json",
                "openapi.json", "openapi.yaml", "api-docs",
                "swagger-ui", "swagger-ui.html", "redoc",
                "rest", "rest/v1", "rest/v2",
                "v1", "v2", "v3", "services",
                "endpoints", "routes", "schema",
                ".well-known/openid-configuration"
            ]))
        return api_wl
