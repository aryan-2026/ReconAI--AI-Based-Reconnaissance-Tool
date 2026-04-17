"""
ReconAI - Wordlist Manager
Manages and selects appropriate wordlists for each recon module.
"""
from pathlib import Path
from typing import Optional
from utils.logger import info, warn


class WordlistManager:
    """
    Manages wordlist selection and fallback logic.
    Supports custom wordlists and auto-detects SecLists.
    """

    SECLISTS_PATHS = [
        Path("/usr/share/seclists"),
        Path("/usr/share/SecLists"),
        Path(Path.home() / "SecLists"),
    ]

    WORDLIST_MAP = {
        "subdomains": [
            "Discovery/DNS/subdomains-top1million-5000.txt",
            "Discovery/DNS/subdomains-top1million-20000.txt",
            "Discovery/DNS/combined_subdomains.txt",
        ],
        "directories": [
            "Discovery/Web-Content/raft-medium-directories.txt",
            "Discovery/Web-Content/raft-large-directories.txt",
            "Discovery/Web-Content/common.txt",
        ],
        "parameters": [
            "Discovery/Web-Content/burp-parameter-names.txt",
            "Discovery/Web-Content/api/api-endpoints.txt",
        ],
        "api": [
            "Discovery/Web-Content/api/api-endpoints.txt",
            "Discovery/Web-Content/api/objects.txt",
        ],
        "cloud": [
            "Discovery/DNS/aws-buckets.txt",
        ]
    }

    def __init__(self, wordlist_dir: Path):
        self.wordlist_dir = wordlist_dir
        self.seclists_base = self._find_seclists()

    def _find_seclists(self) -> Optional[Path]:
        for path in self.SECLISTS_PATHS:
            if path.exists():
                info(f"SecLists found at: {path}")
                return path
        return None

    def get(self, category: str, size: str = "medium") -> Path:
        """
        Get the best available wordlist for a category.
        Falls back to local minimal wordlist if SecLists not found.
        """
        # Try local custom wordlist first
        local = self.wordlist_dir / category
        local.mkdir(parents=True, exist_ok=True)

        local_files = list(local.glob("*.txt"))
        if local_files:
            best = max(local_files, key=lambda f: f.stat().st_size)
            return best

        # Try SecLists
        if self.seclists_base:
            candidates = self.WORDLIST_MAP.get(category, [])
            for candidate in candidates:
                path = self.seclists_base / candidate
                if path.exists():
                    return path

        # Check system wordlists
        system_paths = [
            Path("/usr/share/wordlists/dirb/common.txt"),
            Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
        ]
        for path in system_paths:
            if path.exists() and category == "directories":
                return path

        # Create minimal fallback
        return self._create_fallback(category)

    def _create_fallback(self, category: str) -> Path:
        """Create a minimal fallback wordlist."""
        fallbacks = {
            "subdomains": [
                "www", "mail", "api", "admin", "test", "dev", "staging",
                "beta", "app", "portal", "cdn", "media", "static", "assets",
                "login", "auth", "oauth", "dashboard", "manage", "secure",
                "vpn", "remote", "internal", "corp", "intranet", "gitlab",
                "jenkins", "jira", "confluence", "wiki", "docs", "help"
            ],
            "directories": [
                "admin", "api", "login", "dashboard", "config", "backup",
                "upload", "files", "static", "assets", ".git", ".env",
                "swagger", "graphql", "v1", "v2", "v3", "test", "dev"
            ],
            "api": [
                "api", "api/v1", "api/v2", "graphql", "swagger.json",
                "openapi.json", "api-docs", "rest", "services"
            ],
            "cloud": [
                "backup", "assets", "media", "static", "files", "data",
                "uploads", "images", "logs", "archive", "exports"
            ],
            "parameters": [
                "id", "user", "username", "email", "page", "limit",
                "offset", "search", "q", "query", "token", "key", "redirect"
            ]
        }

        path = self.wordlist_dir / category / "fallback.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        words = fallbacks.get(category, ["test"])
        path.write_text("\n".join(words))
        warn(f"Using minimal fallback wordlist for '{category}' ({len(words)} entries)")
        return path

    def list_available(self) -> dict:
        """List all available wordlists."""
        result = {}
        for category in ["subdomains", "directories", "api", "cloud", "parameters"]:
            wl = self.get(category)
            lines = len(wl.read_text().splitlines()) if wl.exists() else 0
            result[category] = {"path": str(wl), "lines": lines}
        return result
