"""
ReconAI - Cloud Asset Discovery Engine
Discovers exposed cloud infrastructure: S3, GCS, Azure Blob, Firebase, etc.
"""
import asyncio
import re
import json
import logging
from pathlib import Path
from typing import List, Dict
import httpx
from tools.executor import ToolExecutor
from utils.logger import section, info, success, warn

# Suppress noisy httpx/httpcore transport-level INFO logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class CloudDiscovery:
    """
    Discovers cloud assets associated with a target:
    - AWS S3 buckets
    - Google Cloud Storage
    - Azure Blob Storage
    - Firebase databases
    - CloudFront distributions
    """

    # S3 bucket URL patterns
    S3_PATTERNS = [
        "https://{name}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{name}",
        "https://{name}.s3-{region}.amazonaws.com",
    ]

    GCS_PATTERNS = [
        "https://storage.googleapis.com/{name}",
        "https://{name}.storage.googleapis.com",
    ]

    AZURE_PATTERNS = [
        "https://{name}.blob.core.windows.net",
        "https://{name}.azurewebsites.net",
    ]

    FIREBASE_PATTERNS = [
        "https://{name}.firebaseio.com",
        "https://{name}.firebaseapp.com",
    ]

    def __init__(self, executor: ToolExecutor, wordlist_dir: Path, output_dir: Path):
        self.executor     = executor
        self.wordlist_dir = wordlist_dir
        self.output_dir   = output_dir

    async def discover(self, company_name: str, domain: str) -> List[Dict]:
        """
        Full cloud asset discovery for a company/domain.
        """
        section("Cloud Asset Discovery Engine")

        # Generate bucket name candidates
        candidates = self._generate_candidates(company_name, domain)
        info(f"Testing {len(candidates)} cloud asset name candidates...")

        all_assets = []

        # Test all providers in parallel
        results = await asyncio.gather(
            self._check_s3(candidates),
            self._check_gcs(candidates),
            self._check_azure(candidates),
            self._check_firebase(candidates),
        )

        for provider_assets in results:
            all_assets.extend(provider_assets)

        # Run CloudEnum if available
        if self.executor.check_tool("cloud_enum"):
            ce_assets = await self._run_cloud_enum(domain)
            all_assets.extend(ce_assets)

        # Run CloudBrute if available
        if self.executor.check_tool("cloudbrute"):
            cb_assets = await self._run_cloudbrute(company_name, domain)
            all_assets.extend(cb_assets)

        # Deduplicate by URL
        seen_urls = set()
        deduped = []
        for asset in all_assets:
            url = asset.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                deduped.append(asset)
        all_assets = deduped

        # Save results
        self._save_results(all_assets)
        return all_assets

    def _generate_candidates(self, company: str, domain: str) -> List[str]:
        """Generate candidate bucket/storage names from company name and domain."""
        base = domain.split(".")[0].lower()
        company_clean = re.sub(r"[^a-z0-9]", "", company.lower())

        candidates = set()

        # Common patterns
        prefixes   = ["", "dev-", "staging-", "prod-", "test-", "backup-", "data-", "static-", "media-", "assets-", "files-"]
        suffixes   = ["", "-dev", "-staging", "-prod", "-backup", "-data", "-static", "-assets", "-files", "-media", "-bucket"]

        for name in [base, company_clean]:
            for prefix in prefixes:
                for suffix in suffixes:
                    candidate = f"{prefix}{name}{suffix}"
                    if 3 <= len(candidate) <= 63:
                        candidates.add(candidate)

        # Load custom wordlist if available
        wl_path = self.wordlist_dir / "cloud" / "buckets.txt"
        if wl_path.exists():
            for line in wl_path.read_text().splitlines():
                line = line.strip()
                if line:
                    candidates.add(f"{base}-{line}")
                    candidates.add(f"{line}-{base}")

        return list(candidates)[:500]  # Limit to 500

    async def _check_s3(self, candidates: List[str]) -> List[Dict]:
        """Check AWS S3 buckets."""
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            async def check_one(name):
                url = f"https://{name}.s3.amazonaws.com"
                try:
                    r = await client.get(url)
                    if r.status_code in [200, 301, 403]:
                        status = "PUBLIC" if r.status_code == 200 else ("FORBIDDEN" if r.status_code == 403 else "REDIRECT")
                        return {"url": url, "provider": "AWS S3", "name": name, "status": status, "http_code": r.status_code}
                except Exception:
                    pass
                return None

            tasks = [check_one(n) for n in candidates]
            results = await asyncio.gather(*tasks)
            findings = [r for r in results if r]

        if findings:
            info(f"S3: found {len(findings)} buckets")
        return findings

    async def _check_gcs(self, candidates: List[str]) -> List[Dict]:
        """Check Google Cloud Storage buckets."""
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            async def check_one(name):
                url = f"https://storage.googleapis.com/{name}"
                try:
                    r = await client.get(url)
                    if r.status_code in [200, 301, 403]:
                        status = "PUBLIC" if r.status_code == 200 else "RESTRICTED"
                        return {"url": url, "provider": "Google Cloud Storage", "name": name, "status": status, "http_code": r.status_code}
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*[check_one(n) for n in candidates])
            findings = [r for r in results if r]
        return findings

    async def _check_azure(self, candidates: List[str]) -> List[Dict]:
        """Check Azure Blob Storage."""
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            async def check_one(name):
                url = f"https://{name}.blob.core.windows.net"
                try:
                    r = await client.get(url)
                    if r.status_code in [200, 400, 403, 404]:
                        # 400 = exists but wrong request format (still means bucket exists)
                        if r.status_code in [200, 400, 403]:
                            return {"url": url, "provider": "Azure Blob", "name": name, "status": "EXISTS", "http_code": r.status_code}
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*[check_one(n) for n in candidates[:100]])
            findings = [r for r in results if r]
        return findings

    async def _check_firebase(self, candidates: List[str]) -> List[Dict]:
        """Check Firebase databases."""
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            async def check_one(name):
                url = f"https://{name}.firebaseio.com/.json"
                try:
                    r = await client.get(url)
                    if r.status_code == 200:
                        return {"url": url, "provider": "Firebase", "name": name, "status": "PUBLIC_DATABASE", "http_code": 200}
                    elif r.status_code == 401:
                        return {"url": url, "provider": "Firebase", "name": name, "status": "EXISTS_PROTECTED", "http_code": 401}
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*[check_one(n) for n in candidates[:100]])
            findings = [r for r in results if r]
        return findings

    async def _run_cloudbrute(self, company_name: str, domain: str) -> List[Dict]:
        """
        Run CloudBrute for cloud asset discovery.
        CloudBrute: https://github.com/0xsha/CloudBrute
        Install: go install github.com/0xsha/CloudBrute@latest
        """
        wordlist = self._get_cloud_wordlist()
        findings = []
        
        for provider in ["aws", "gcp", "azure"]:
            output = await self.executor.run_async(
                [
                    "cloudbrute",
                    "-d", company_name,
                    "-k", domain,
                    "-m", provider,
                    "-w", str(wordlist),
                    "-t", "20",
                ],
                timeout=300
            )
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    # CloudBrute outputs lines like: [FOUND] https://bucket.s3.amazonaws.com
                    if "FOUND" in line or "found" in line.lower() or line.startswith("http"):
                        url = line.split("]")[-1].strip() if "]" in line else line
                        if url.startswith("http"):
                            findings.append({
                                "url":      url,
                                "provider": f"cloudbrute_{provider}",
                                "name":     url.split("/")[2],
                                "status":   "FOUND",
                                "tool":     "cloudbrute",
                            })
        
        if findings:
            info(f"CloudBrute: {len(findings)} cloud assets found")
        return findings

    def _get_cloud_wordlist(self) -> "Path":
        """Return cloud asset wordlist path."""
        candidates = [
            Path("/usr/share/seclists/Discovery/WebContent/burp-parameter-names.txt"),
            self.wordlist_dir / "cloud" / "cloud_names.txt",
        ]
        for p in candidates:
            if p.exists():
                return p
        # Fallback wordlist already in cloud_discovery candidates
        fallback = self.wordlist_dir / "cloud" / "cloud_names.txt"
        if fallback.exists():
            return fallback
        # Create minimal fallback
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.write_text("\n".join([
            "backup", "data", "files", "media", "static", "assets",
            "uploads", "images", "docs", "logs", "dev", "staging",
            "prod", "test", "public", "private", "config", "deploy",
        ]))
        return fallback

    async def _run_cloud_enum(self, domain: str) -> List[Dict]:
        """Run cloud_enum tool if available."""
        output = await self.executor.run_async(
            ["cloud_enum", "-k", domain, "--disable-gcp", "--disable-azure"],
            timeout=180
        )
        findings = []
        if output:
            for line in output.splitlines():
                if "OPEN" in line or "EXISTS" in line or "PUBLIC" in line:
                    findings.append({"url": line.strip(), "provider": "cloud_enum", "status": "FOUND"})
        return findings

    def _save_results(self, assets: List[Dict]):
        """Save cloud assets to output files."""
        json_path = self.output_dir / "cloud_assets.json"
        json_path.write_text(json.dumps(assets, indent=2))

        lines = [f"[{a['provider']}] {a['url']} [{a.get('status', '')}]" for a in assets]
        self.executor.save_results("cloud_assets.txt", lines)

        public = [a for a in assets if a.get("status") in ["PUBLIC", "PUBLIC_DATABASE"]]
        if public:
            from utils.logger import console
            console.print(f"\n[bold red]  ☁️  PUBLIC CLOUD ASSETS FOUND: {len(public)}![/bold red]")
            for a in public:
                console.print(f"  [red]  • {a['url']}[/red]")

        success(f"Cloud assets: {len(assets)} found ({len(public)} public)")
