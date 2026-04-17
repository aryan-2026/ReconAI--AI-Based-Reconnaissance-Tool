"""
ReconAI - Screenshot Recon Engine
Captures and AI-classifies screenshots of live web services.
"""
import asyncio
import json
import subprocess
from pathlib import Path
from typing import List, Dict
from tools.executor import ToolExecutor
from utils.logger import section, info, success, warn


class ScreenshotEngine:
    """
    Captures screenshots of all live web services using gowitness.
    Falls back gracefully if gowitness is unavailable.
    Rule-based + optional AI classification of each service type.
    """

    CATEGORY_PRIORITY = {
        "login_panel":       9,
        "admin_dashboard":   10,
        "monitoring_system": 8,
        "internal_tool":     8,
        "api_service":       7,
        "dev_environment":   8,
        "file_upload":       9,
        "unknown":           3,
    }

    def __init__(self, executor: ToolExecutor, output_dir: Path, model_router=None):
        self.executor        = executor
        self.output_dir      = output_dir
        self.screenshots_dir = output_dir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.model_router    = model_router
        self._gowitness_ver  = None   # detected on first use

    def _detect_gowitness_version(self) -> str:
        """Detect gowitness major version (2 vs 3) to pick correct CLI."""
        if self._gowitness_ver:
            return self._gowitness_ver
        try:
            result = subprocess.run(
                ["gowitness", "version"],
                capture_output=True, text=True, timeout=5
            )
            out = (result.stdout + result.stderr).lower()
            if "version 3" in out or " v3." in out or "3.0" in out:
                self._gowitness_ver = "3"
            else:
                self._gowitness_ver = "2"
        except Exception:
            self._gowitness_ver = "2"
        info(f"gowitness version detected: v{self._gowitness_ver}")
        return self._gowitness_ver

    async def capture_and_classify(self, live_hosts: List[Dict]) -> List[Dict]:
        """Capture screenshots and classify all live services."""
        section("Screenshot Recon Engine")

        if not live_hosts:
            warn("No live hosts for screenshots")
            return []

        host_urls = [
            h["url"] if isinstance(h, dict) else (
                h if h.startswith("http") else f"https://{h}"
            )
            for h in live_hosts
        ]

        # Capture screenshots — gowitness primary, EyeWitness secondary
        if self.executor.check_tool("gowitness"):
            await self._gowitness(host_urls)
        else:
            warn("gowitness not found — skipping gowitness capture")

        # EyeWitness runs alongside gowitness for additional coverage
        await self._eyewitness(host_urls)

        # Classify all hosts using rule-based + optional AI
        classified = []
        for host in live_hosts:
            if isinstance(host, str):
                host = {
                    "url": host if host.startswith("http") else f"https://{host}",
                    "title": "", "technologies": []
                }

            category = self._classify_host(host)
            priority = self.CATEGORY_PRIORITY.get(category, 3)

            classified.append({
                **host,
                "category":       category,
                "priority_score": priority,
                "screenshot":     self._get_screenshot_path(host.get("url", ""))
            })

        classified.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
        self._save_results(classified)
        success(f"Classified {len(classified)} services")
        return classified

    async def _eyewitness(self, urls: List[str]):
        """
        Run EyeWitness for additional screenshot capture.
        EyeWitness: https://github.com/RedSiege/EyeWitness
        Complements gowitness with different rendering engine.
        """
        if not self.executor.check_tool("EyeWitness") and not self.executor.check_tool("eyewitness"):
            warn("EyeWitness not found — skipping (git clone https://github.com/RedSiege/EyeWitness && pip install -r requirements.txt)")
            return

        tool = "EyeWitness" if self.executor.check_tool("EyeWitness") else "eyewitness"
        hosts_file = self.output_dir / "live_hosts_for_eyewitness.txt"
        hosts_file.write_text("\n".join(urls))
        ew_out = self.screenshots_dir / "eyewitness"
        ew_out.mkdir(parents=True, exist_ok=True)

        await self.executor.run_async(
            [
                tool,
                "--web",
                "-f", str(hosts_file),
                "-d", str(ew_out),
                "--timeout", "10",
                "--threads", "5",
                "--no-prompt",
            ],
            timeout=600
        )
        info(f"EyeWitness screenshots saved to {ew_out}")

    async def _gowitness(self, urls: List[str]):
        """Run gowitness — handles both v2 and v3 CLI syntax."""
        hosts_file = self.output_dir / "live_hosts_for_screenshots.txt"
        hosts_file.write_text("\n".join(urls))

        ver = self._detect_gowitness_version()

        if ver == "3":
            # gowitness v3: `gowitness scan file -f hosts.txt --screenshot-path ./screenshots`
            cmd = [
                "gowitness", "scan", "file",
                "-f", str(hosts_file),
                "--screenshot-path", str(self.screenshots_dir),
                "--timeout", "10",
                "--threads", "5"
            ]
        else:
            # gowitness v2: `gowitness file -f hosts.txt -P ./screenshots`
            cmd = [
                "gowitness", "file",
                "-f", str(hosts_file),
                "-P", str(self.screenshots_dir),
                "--timeout", "10",
                "--threads", "5"
            ]

        await self.executor.run_async(cmd, timeout=600)

    def _classify_host(self, host: Dict) -> str:
        """Rule-based classification — fast, no LLM needed."""
        url      = host.get("url",   "").lower()
        title    = host.get("title", "").lower()
        techs    = " ".join(t.lower() for t in host.get("technologies", []))
        combined = f"{url} {title} {techs}"

        rules = [
            (["admin", "administrator", "manage", "management", "console", "cpanel"], "admin_dashboard"),
            (["login", "sign in", "signin", "auth", "authenticate", "sso", "ldap"],   "login_panel"),
            (["grafana", "kibana", "prometheus", "zabbix", "nagios", "datadog",
              "monitor", "alertmanager"],                                               "monitoring_system"),
            (["jira", "confluence", "jenkins", "gitlab", "github", "sonar",
              "internal", "intranet"],                                                  "internal_tool"),
            (["api", "swagger", "openapi", "graphql", "rest", "endpoint",
              "graphiql"],                                                              "api_service"),
            (["dev", "staging", "test", "qa", "develop", "sandbox", "beta"],          "dev_environment"),
            (["upload", "file", "attachment", "document", "media"],                   "file_upload"),
        ]

        for keywords, category in rules:
            if any(kw in combined for kw in keywords):
                return category

        # Optional AI classification for ambiguous cases
        if self.model_router:
            try:
                result = self.model_router.classify_screenshot(
                    url,
                    host.get("title", ""),
                    ", ".join(host.get("technologies", []))
                )
                if result in self.CATEGORY_PRIORITY:
                    return result
            except Exception:
                pass

        return "unknown"

    def _get_screenshot_path(self, url: str) -> str:
        import hashlib
        if not url:
            return ""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        for ext in [".png", ".jpg", ".jpeg"]:
            path = self.screenshots_dir / f"{url_hash}{ext}"
            if path.exists():
                return str(path)
        return ""

    def _save_results(self, classified: List[Dict]):
        json_path = self.output_dir / "screenshot_classification.json"
        json_path.write_text(json.dumps(classified, indent=2))

        from collections import Counter
        categories = Counter(h["category"] for h in classified)

        from utils.logger import console
        console.print("\n[bold cyan]  Service Classification Summary:[/bold cyan]")
        for cat, count in sorted(categories.items(), key=lambda x: -self.CATEGORY_PRIORITY.get(x[0], 0)):
            priority = self.CATEGORY_PRIORITY.get(cat, 0)
            color = "red" if priority >= 8 else "yellow" if priority >= 6 else "dim"
            console.print(f"  [{color}]  {cat}: {count} host(s)[/{color}]")
