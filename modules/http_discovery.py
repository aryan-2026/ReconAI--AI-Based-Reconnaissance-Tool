"""
ReconAI - HTTP Service Discovery & Technology Fingerprinting
Uses httpx to probe live web services.
"""
import asyncio
import json
import subprocess
from pathlib import Path
from typing import List, Dict
from tools.executor import ToolExecutor
from utils.logger import log, section, info, success, warn


class HTTPDiscovery:
    """
    Discovers live HTTP/HTTPS services and fingerprints their technology stack.
    """

    def __init__(self, executor: ToolExecutor, output_dir: Path):
        self.executor   = executor
        self.output_dir = output_dir
        self._httpx_list_flag = None   # auto-detected on first use

    def _detect_httpx_flag(self) -> str:
        """
        Auto-detect the correct input-list flag for the installed httpx version.
        ProjectDiscovery httpx uses -l
        Some older/forked versions use -list
        Falls back to -l (most common).
        """
        if self._httpx_list_flag:
            return self._httpx_list_flag
        try:
            result = subprocess.run(
                ["httpx", "-help"],
                capture_output=True, text=True, timeout=5
            )
            help_text = result.stdout + result.stderr
            if "-list" in help_text and "-l " not in help_text:
                self._httpx_list_flag = "-list"
            else:
                self._httpx_list_flag = "-l"
        except Exception:
            self._httpx_list_flag = "-l"
        info(f"httpx input flag detected: {self._httpx_list_flag}")
        return self._httpx_list_flag

    async def discover(self, subdomains: List[str]) -> List[Dict]:
        """
        Probe all subdomains for live HTTP services.
        Returns enriched list of live host objects.
        """
        section("HTTP Service Discovery")

        # Always ensure the root domain itself is in the list
        # (subdomain enumeration may find zero results for small targets)
        probe_list = list(set(subdomains))
        if not probe_list:
            warn("No subdomains to probe — nothing to scan")
            return []

        # Write probe list to file (always overwrite with current list)
        subs_file = self.output_dir / "resolved_subdomains.txt"
        subs_file.write_text("\n".join(probe_list))
        info(f"Probing {len(probe_list)} host(s) with httpx")

        if not self.executor.check_tool("httpx"):
            warn("httpx not found — falling back to Python HTTP check")
            return await self._fallback_check(probe_list)

        list_flag = self._detect_httpx_flag()
        httpx_out = self.output_dir / "httpx_raw.jsonl"

        output = await self.executor.run_async(
            [
                "httpx",
                list_flag, str(subs_file),
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-follow-redirects",
                "-threads", "50",
                "-timeout", "10",
                "-o", str(httpx_out)
            ],
            timeout=600
        )

        # Prefer the -o output file (more reliable than stdout capture)
        raw_lines = []
        if httpx_out.exists() and httpx_out.stat().st_size > 0:
            raw_lines = httpx_out.read_text().splitlines()
            info(f"httpx output file: {len(raw_lines)} line(s)")
        elif output:
            raw_lines = output.splitlines()
            info(f"httpx stdout: {len(raw_lines)} line(s)")
        else:
            warn("httpx returned no output — falling back to Python HTTP check")
            return await self._fallback_check(probe_list)

        hosts = []
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = self._parse_httpx_result(obj)
                if host:
                    hosts.append(host)
            except json.JSONDecodeError:
                if line.startswith("http"):
                    hosts.append({
                        "url":          line,
                        "domain":       line.split("//")[-1].split("/")[0],
                        "status_code":  200,
                        "title":        "",
                        "technologies": [],
                        "server":       "",
                        "cdn":          "",
                        "waf":          ""
                    })

        # If httpx parsed nothing, try Python fallback
        if not hosts:
            warn("httpx parsed 0 hosts — running Python fallback probe")
            hosts = await self._fallback_check(probe_list)

        self._save_hosts(hosts)
        success(f"Discovered {len(hosts)} live HTTP services")
        return hosts

    def _parse_httpx_result(self, obj: dict) -> Dict:
        """Parse a single httpx JSON result line."""
        url = obj.get("url", obj.get("input", ""))
        if not url:
            return None

        domain = url.split("//")[-1].split("/")[0].split(":")[0]

        # Extract technologies
        techs = []
        tech_data = obj.get("tech", obj.get("technologies", []))
        if isinstance(tech_data, list):
            techs = tech_data
        elif isinstance(tech_data, dict):
            techs = list(tech_data.keys())

        # Detect CDN/WAF from headers
        headers = obj.get("response_headers", {})
        cdn = self._detect_cdn(headers)
        waf = self._detect_waf(headers)

        return {
            "url":          url,
            "domain":       domain,
            "status_code":  obj.get("status_code", 0),
            "title":        obj.get("title", ""),
            "technologies": techs,
            "server":       headers.get("server", headers.get("Server", "")),
            "cdn":          cdn,
            "waf":          waf,
            "content_length": obj.get("content_length", 0),
            "final_url":    obj.get("final_url", url),
            "ip":           obj.get("host", "")
        }

    def _detect_cdn(self, headers: dict) -> str:
        cdn_signals = {
            "cloudflare":  ["cf-ray", "cf-cache-status"],
            "fastly":      ["x-served-by", "x-cache"],
            "akamai":      ["x-check-cacheable", "akamai"],
            "cloudfront":  ["x-amz-cf-id"],
            "incapsula":   ["x-iinfo"],
        }
        h_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for cdn, signals in cdn_signals.items():
            if any(s in h_lower for s in signals):
                return cdn
        return ""

    def _detect_waf(self, headers: dict) -> str:
        waf_signals = {
            "cloudflare":   "cf-ray",
            "sucuri":       "x-sucuri-id",
            "akamai":       "x-check-cacheable",
            "incapsula":    "x-iinfo",
            "barracuda":    "barra_counter_session",
        }
        h_lower = {k.lower(): v for k, v in headers.items()}
        for waf, signal in waf_signals.items():
            if signal in h_lower:
                return waf
        return ""

    def _save_hosts(self, hosts: List[Dict]):
        """Save live hosts to output files."""
        # Plain URLs
        urls = [h["url"] for h in hosts]
        self.executor.save_results("live_hosts.txt", urls)

        # Full JSON
        json_path = self.output_dir / "live_hosts.json"
        json_path.write_text(json.dumps(hosts, indent=2))

    async def _fallback_check(self, subdomains: List[str]) -> List[Dict]:
        """
        Pure-Python HTTP probe fallback using the httpx library.
        Works even when the httpx CLI binary is broken/missing.
        """
        import logging
        import httpx as httpx_lib
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

        info(f"Python fallback: probing {len(subdomains[:100])} hosts...")
        hosts = []

        async def check_one(sub: str):
            # Normalise — strip any existing scheme
            bare = sub.replace("https://", "").replace("http://", "").split("/")[0]
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{bare}"
                    async with httpx_lib.AsyncClient(
                        verify=False, timeout=10,
                        follow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 ReconAI/2.0"}
                    ) as client:
                        r = await client.get(url)
                        return {
                            "url":          str(r.url),
                            "domain":       bare,
                            "status_code":  r.status_code,
                            "title":        self._extract_title(r.text),
                            "technologies": [],
                            "server":       r.headers.get("server", ""),
                            "cdn":          self._detect_cdn(dict(r.headers)),
                            "waf":          self._detect_waf(dict(r.headers)),
                            "content_length": len(r.content),
                            "final_url":    str(r.url),
                            "ip":           ""
                        }
                except Exception:
                    continue
            return None

        results = await asyncio.gather(*[check_one(s) for s in subdomains[:100]])
        hosts = [r for r in results if r is not None]
        self._save_hosts(hosts)
        success(f"Python fallback: found {len(hosts)} live services")
        return hosts

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r"<title[^>]*>(.+?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:100] if match else ""
