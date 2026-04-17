"""
ReconAI - Scope Parser
Parses, normalizes, and enforces bug bounty scope rules.
"""
import re
from typing import List, Tuple
from urllib.parse import urlparse
from utils.logger import log, info, warn


class ScopeParser:
    """
    Handles all scope validation for recon operations.
    Prevents scanning out-of-scope assets.

    Scope logic:
      - "*.example.com"  → wildcard, covers all subdomains
      - "example.com"    → explicit; we ALSO accept all subdomains of it
                           (a user who types "example.com" wants to recon
                            that target AND its subdomains, not just the bare root)
    """

    def __init__(self):
        self.in_scope:     List[str] = []
        self.out_of_scope: List[str] = []
        self.wildcards:    List[str] = []
        self.explicit:     List[str] = []

    def parse(self, scope_input: str, oos_input: str = "") -> Tuple[List[str], List[str]]:
        self.in_scope     = self._normalize_list(scope_input)
        self.out_of_scope = self._normalize_list(oos_input)

        for domain in self.in_scope:
            if domain.startswith("*."):
                self.wildcards.append(domain[2:])   # strip *.
            else:
                self.explicit.append(domain)

        info(f"Scope loaded: {len(self.in_scope)} targets | {len(self.out_of_scope)} OOS exclusions")
        info(f"Wildcards: {self.wildcards} | Explicit: {self.explicit}")
        return self.in_scope, self.out_of_scope

    def _normalize_list(self, raw: str) -> List[str]:
        items = []
        for line in re.split(r"[\n,;]+", raw):
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if "://" in line:
                parsed = urlparse(line)
                line = parsed.netloc or parsed.path
            line = line.split("/")[0].strip()
            if line:
                items.append(line)
        return list(set(items))

    def is_in_scope(self, domain: str) -> bool:
        """
        Check if a given domain is within scope.

        Key rule: if the user enters "example.com" (no wildcard),
        we treat it as implicitly covering *.example.com too.
        A user who scopes "example.com" wants to recon the target
        AND all its subdomains — not just the bare root domain.
        """
        domain = domain.lower().strip()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        # Out-of-scope check always wins
        for oos in self.out_of_scope:
            if domain == oos or domain.endswith("." + oos):
                return False

        # Wildcard in-scope
        for wc in self.wildcards:
            if domain == wc or domain.endswith("." + wc):
                return True

        # Explicit in-scope — ALSO accept subdomains of explicit entries
        for inscope in self.explicit:
            if domain == inscope or domain.endswith("." + inscope):
                return True

        return False

    def filter_domains(self, domains: List[str]) -> List[str]:
        filtered = [d for d in domains if self.is_in_scope(d)]
        removed  = len(domains) - len(filtered)
        if removed > 0:
            warn(f"Removed {removed} out-of-scope domains from results")
        return filtered

    def get_root_domains(self) -> List[str]:
        roots = set()
        for wc in self.wildcards:
            roots.add(wc)
        for exp in self.explicit:
            parts = exp.split(".")
            if len(parts) >= 2:
                roots.add(".".join(parts[-2:]))
        return list(roots)

    def summary(self) -> dict:
        return {
            "in_scope_count":     len(self.in_scope),
            "out_of_scope_count": len(self.out_of_scope),
            "wildcards":          self.wildcards,
            "explicit":           self.explicit,
            "root_domains":       self.get_root_domains()
        }
