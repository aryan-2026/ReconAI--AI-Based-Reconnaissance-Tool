"""
ReconAI - Dataset Manager & Report Generator
Manages all collected recon data and generates final reports.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from utils.logger import section, info, success, stat


class DatasetManager:
    """
    Central data store for all recon results.
    Handles loading, merging, and final report generation.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, Any] = {
            "target":               "",
            "scan_start":           "",
            "scan_end":             "",
            "subdomains":           [],
            "resolved_subdomains":  [],
            "live_hosts":           [],
            "open_ports":           {},
            "technologies":         [],
            "endpoints":            [],
            "apis":                 [],
            "cloud_assets":         [],
            "js_urls":              [],
            "js_endpoints":         [],
            "js_secrets":           [],
            "vulnerability_hints":  [],
            "high_priority_targets": [],
            "ai_analysis":          {}
        }

    def set_target(self, target: str):
        self._data["target"]     = target
        self._data["scan_start"] = datetime.now().isoformat()

    def update(self, key: str, value: Any):
        """Update a data field."""
        self._data[key] = value

    def append(self, key: str, items: List):
        """Append to a list field."""
        if key not in self._data:
            self._data[key] = []
        existing = set(
            json.dumps(i, sort_keys=True) if isinstance(i, dict) else str(i)
            for i in self._data[key]
        )
        for item in items:
            item_key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
            if item_key not in existing:
                self._data[key].append(item)
                existing.add(item_key)

    def get(self, key: str = None) -> Any:
        """Get a data field or all data."""
        if key:
            return self._data.get(key, None)
        return self._data

    def load_from_files(self):
        """Load previously saved recon data from output files."""
        def read_lines(filename):
            p = self.output_dir / filename
            return p.read_text().splitlines() if p.exists() else []

        def read_json(filename):
            p = self.output_dir / filename
            try:
                return json.loads(p.read_text()) if p.exists() else []
            except Exception:
                return []

        self._data["subdomains"]          = read_lines("subdomains_raw.txt")
        self._data["resolved_subdomains"] = read_lines("resolved_subdomains.txt")
        self._data["live_hosts"]          = read_json("live_hosts.json") or read_lines("live_hosts.txt")
        self._data["endpoints"]           = read_lines("endpoints.txt")
        self._data["js_urls"]             = read_lines("js_urls.txt")
        self._data["js_endpoints"]        = read_lines("js_endpoints.txt")
        self._data["js_secrets"]          = read_json("js_secrets.json")
        self._data["cloud_assets"]        = read_json("cloud_assets.json")
        self._data["vulnerability_hints"] = read_json("vulnerability_hints.json")
        self._data["open_ports"]          = read_json("open_ports.json")

    def compute_high_priority_targets(self) -> List[Dict]:
        """Identify and rank high-priority targets from all data."""
        from core.config import PRIORITY_KEYWORDS

        targets = []
        seen = set()

        # From classified live hosts
        for host in self._data.get("live_hosts", []):
            if isinstance(host, dict):
                url      = host.get("url", "")
                priority = host.get("priority_score", 0)
                if url and url not in seen and priority >= 7:
                    targets.append({
                        "target":   url,
                        "type":     "web_service",
                        "category": host.get("category", ""),
                        "score":    priority,
                        "reason":   f"Classified as {host.get('category', 'high-value')} with priority {priority}/10",
                        "techs":    host.get("technologies", [])
                    })
                    seen.add(url)

        # From vulnerability hints
        critical_targets = {}
        for hint in self._data.get("vulnerability_hints", []):
            target = hint.get("target", "")
            if not target or target in ["(global)"]:
                continue
            score = hint.get("score", 0)
            if target not in critical_targets or critical_targets[target]["score"] < score:
                critical_targets[target] = hint

        for target, hint in critical_targets.items():
            if target not in seen and hint.get("score", 0) >= 8:
                targets.append({
                    "target":   target,
                    "type":     "vulnerability_hint",
                    "category": hint.get("hint_type", ""),
                    "score":    hint.get("score", 0),
                    "reason":   hint.get("reason", ""),
                    "priority": hint.get("priority", "HIGH")
                })
                seen.add(target)

        # Sort by score
        targets.sort(key=lambda t: t.get("score", 0), reverse=True)
        self._data["high_priority_targets"] = targets[:50]
        return targets[:50]

    def generate_final_report(self, ai_analysis: dict = None) -> Dict:
        """Generate the final structured JSON report."""
        section("Generating Final Report")

        self._data["scan_end"] = datetime.now().isoformat()

        if ai_analysis:
            self._data["ai_analysis"] = ai_analysis

        # Compute high priority targets
        self.compute_high_priority_targets()

        # Build summary stats
        summary = {
            "target":             self._data["target"],
            "scan_duration":      self._get_duration(),
            "subdomains_found":   len(self._data["subdomains"]),
            "live_hosts_found":   len(self._data["live_hosts"]),
            "endpoints_found":    len(self._data["endpoints"]),
            "apis_found":         len(self._data["apis"]),
            "cloud_assets_found": len(self._data["cloud_assets"]),
            "js_secrets_found":   len(self._data["js_secrets"]),
            "vuln_hints_count":   len(self._data["vulnerability_hints"]),
            "critical_hints":     len([h for h in self._data["vulnerability_hints"] if h.get("priority") == "CRITICAL"]),
            "high_hints":         len([h for h in self._data["vulnerability_hints"] if h.get("priority") == "HIGH"]),
        }

        # Final JSON report
        report = {
            "meta":                  summary,
            "target":                self._data["target"],
            "subdomains":            self._data["subdomains"],
            "live_hosts":            self._data["live_hosts"][:100],
            "open_ports":            self._data["open_ports"],
            "technologies":          self._data["technologies"],
            "endpoints":             self._data["endpoints"][:500],
            "apis":                  self._data["apis"],
            "cloud_assets":          self._data["cloud_assets"],
            "js_secrets":            self._data["js_secrets"],
            "vulnerability_hints":   self._data["vulnerability_hints"],
            "high_priority_targets": self._data["high_priority_targets"],
            "ai_analysis":           self._data.get("ai_analysis", {})
        }

        # Save full report
        report_path = self.output_dir / "final_report.json"
        report_path.write_text(json.dumps(report, indent=2))

        # Generate markdown summary
        self._generate_markdown_report(summary, report)

        success(f"Final report saved → {report_path}")
        self._print_summary(summary)
        return report

    def _get_duration(self) -> str:
        try:
            start = datetime.fromisoformat(self._data["scan_start"])
            end   = datetime.fromisoformat(self._data["scan_end"])
            delta = end - start
            mins  = int(delta.total_seconds() // 60)
            secs  = int(delta.total_seconds() % 60)
            return f"{mins}m {secs}s"
        except Exception:
            return "N/A"

    def _generate_markdown_report(self, summary: dict, report: dict):
        """Generate a human-readable markdown report."""
        md = f"""# 🔍 ReconAI Report — {report['target']}

**Scan Date:** {self._data.get('scan_start', 'N/A')}
**Duration:** {summary.get('scan_duration', 'N/A')}

---

## 📊 Summary

| Metric | Count |
|--------|-------|
| Subdomains Found | {summary['subdomains_found']} |
| Live Hosts | {summary['live_hosts_found']} |
| Endpoints | {summary['endpoints_found']} |
| APIs Discovered | {summary['apis_found']} |
| Cloud Assets | {summary['cloud_assets_found']} |
| JS Secrets | {summary['js_secrets_found']} |
| Vuln Hints (Critical) | {summary['critical_hints']} |
| Vuln Hints (High) | {summary['high_hints']} |

---

## 🎯 High Priority Targets

"""
        for target in report.get("high_priority_targets", [])[:20]:
            md += f"### [{target.get('score', 0)}/10] {target.get('target', '')}\n"
            md += f"- **Type:** {target.get('category', '')}\n"
            md += f"- **Reason:** {target.get('reason', '')}\n\n"

        md += "---\n\n## 🚨 Critical Vulnerability Hints\n\n"
        for hint in report.get("vulnerability_hints", []):
            if hint.get("priority") == "CRITICAL":
                md += f"- **[{hint['hint_type']}]** `{hint['target'][:80]}`\n"
                md += f"  - {hint['reason']}\n\n"

        if report.get("ai_analysis"):
            md += "---\n\n## 🤖 AI Analysis\n\n"
            analysis = report["ai_analysis"]
            md += f"{analysis.get('analysis_summary', '')}\n\n"
            md += "### Next Steps\n"
            for step in analysis.get("next_steps", []):
                md += f"- {step}\n"

        md_path = self.output_dir / "report.md"
        md_path.write_text(md)
        success(f"Markdown report saved → {md_path}")

    def _print_summary(self, summary: dict):
        from utils.logger import console
        console.print("\n[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]")
        console.print("[bold green]  ✅ RECON COMPLETE — FINAL SUMMARY[/bold green]")
        console.print("[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]")
        for k, v in summary.items():
            stat(k.replace("_", " ").title(), v)
        console.print("")
