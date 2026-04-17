"""
ReconAI - Port Scanning Engine
Fast port discovery using rustscan (with nmap fallback).
Handles rustscan v1/v2 CLI differences.
"""
import asyncio
import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict
from tools.executor import ToolExecutor
from utils.logger import section, info, success, warn


class PortScanner:
    """
    Identifies open ports and services.
    Strategy: rustscan (fast) → nmap (reliable fallback)
    """

    INTERESTING_PORTS = {
        21:    "FTP",           22:    "SSH",
        23:    "Telnet",        25:    "SMTP",
        53:    "DNS",           80:    "HTTP",
        110:   "POP3",         143:    "IMAP",
        443:   "HTTPS",        445:    "SMB",
        465:   "SMTPS",        587:    "SMTP-TLS",
        993:   "IMAPS",        995:    "POP3S",
        1433:  "MSSQL",       1521:    "Oracle",
        2181:  "Zookeeper",   2375:    "Docker",
        2376:  "Docker-TLS",  3000:    "Grafana/NodeJS",
        3306:  "MySQL",        3389:    "RDP",
        4848:  "GlassFish",   5432:    "PostgreSQL",
        5601:  "Kibana",       5900:    "VNC",
        6379:  "Redis",        6443:    "K8s-API",
        7474:  "Neo4j",        8080:    "HTTP-Alt",
        8443:  "HTTPS-Alt",   8500:    "Consul",
        8888:  "Jupyter/Alt",  9000:    "SonarQube",
        9090:  "Prometheus",   9200:    "Elasticsearch",
        9092:  "Kafka",       10250:    "Kubelet",
        11211: "Memcached",   27017:    "MongoDB",
        50000: "Jenkins",
    }

    def __init__(self, executor: ToolExecutor, output_dir: Path):
        self.executor   = executor
        self.output_dir = output_dir
        self._rustscan_args = None   # detected on first use

    def _detect_rustscan_syntax(self) -> str:
        """
        Detect rustscan version to use correct argument syntax.
        v1: rustscan -a HOST -- nmap_args
        v2: rustscan --addresses HOST -- nmap_args  (also accepts -a)
        Returns "v1" or "v2".
        """
        if self._rustscan_args:
            return self._rustscan_args
        try:
            result = subprocess.run(
                ["rustscan", "--version"],
                capture_output=True, text=True, timeout=5
            )
            out = result.stdout + result.stderr
            # v2+ shows "rustscan 2." in version string
            if "2." in out or "rustscan 2" in out.lower():
                self._rustscan_args = "v2"
            else:
                self._rustscan_args = "v1"
        except Exception:
            self._rustscan_args = "v1"
        info(f"rustscan syntax: {self._rustscan_args}")
        return self._rustscan_args

    async def scan(self, hosts: List[str], top_ports: int = 1000) -> Dict[str, List[Dict]]:
        section("Port Scanning Engine")

        if not hosts:
            warn("No hosts provided for port scanning")
            return {}

        # Clean hosts — strip protocols if accidentally included
        clean_hosts = []
        for h in hosts[:50]:
            h = h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if h:
                clean_hosts.append(h)

        clean_hosts = list(set(clean_hosts))
        if len(hosts) > 50:
            warn(f"Port scan limited to 50 hosts (had {len(hosts)})")

        results = {}
        if self.executor.check_tool("rustscan"):
            results = await self._rustscan(clean_hosts, top_ports)
            # If rustscan produced no results, fall through to nmap
            if not results and self.executor.check_tool("nmap"):
                warn("rustscan returned nothing — falling back to nmap")
                results = await self._nmap(clean_hosts, top_ports)
        elif self.executor.check_tool("nmap"):
            results = await self._nmap(clean_hosts, top_ports)
        else:
            warn("Neither rustscan nor nmap found — skipping port scan")
            return {}

        self._save_results(results)
        return results

    async def _rustscan(self, hosts: List[str], top_ports: int) -> Dict[str, List[Dict]]:
        info(f"rustscan: scanning {len(hosts)} host(s)...")
        ver = self._detect_rustscan_syntax()

        # Build address argument — rustscan takes comma-separated or single
        addr_str = ",".join(hosts)

        cmd = [
            "rustscan",
            "-a", addr_str,
            "--ulimit", "5000",
            "-b", "500",
            "--timeout", "3000",
            "--tries", "1",
            "--",               # pass remaining args to nmap
            "-sV", "--version-light",
            "--open",
            f"--top-ports={top_ports}",
            "-T4",
        ]

        output = await self.executor.run_async(cmd, timeout=600)

        if not output:
            return {}

        return self._parse_nmap_output(output)

    async def _nmap(self, hosts: List[str], top_ports: int) -> Dict[str, List[Dict]]:
        info(f"nmap: scanning {len(hosts)} host(s)...")

        hosts_file = self.output_dir / "scan_targets.txt"
        hosts_file.write_text("\n".join(hosts))
        nmap_out   = self.output_dir / "nmap_output.txt"

        output = await self.executor.run_async(
            [
                "nmap",
                "-iL", str(hosts_file),
                f"--top-ports={top_ports}",
                "-sV", "--version-light",
                "--open",
                "-T4",
                "-oN", str(nmap_out),
            ],
            timeout=900,
        )

        # Read from file for reliability (nmap writes output even if stdout captured)
        raw = ""
        if nmap_out.exists() and nmap_out.stat().st_size > 0:
            raw = nmap_out.read_text()
        elif output:
            raw = output

        return self._parse_nmap_output(raw)

    def _parse_nmap_output(self, output: str) -> Dict[str, List[Dict]]:
        """Parse nmap-format text output (used for both nmap and rustscan output)."""
        results: Dict[str, List[Dict]] = {}
        current_host = None

        for line in output.splitlines():
            # Match host header: "Nmap scan report for hostname (ip)" or just "for ip"
            host_match = re.search(
                r"Nmap scan report for (?:(\S+)\s+\(([^)]+)\)|(\S+))", line
            )
            if host_match:
                # Prefer hostname over IP
                current_host = host_match.group(1) or host_match.group(3)
                if current_host not in results:
                    results[current_host] = []
                continue

            # Match open port line: "80/tcp  open  http  Apache httpd 2.4.1"
            port_match = re.match(
                r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?", line
            )
            if port_match and current_host:
                port_num = int(port_match.group(1))
                service  = port_match.group(3).strip()
                version  = (port_match.group(4) or "").strip()
                results[current_host].append({
                    "port":        port_num,
                    "protocol":    port_match.group(2),
                    "state":       "open",
                    "service":     service,
                    "version":     version,
                    "known":       self.INTERESTING_PORTS.get(port_num, ""),
                    "interesting": port_num in self.INTERESTING_PORTS,
                })

        return {h: p for h, p in results.items() if p}

    def _save_results(self, results: Dict[str, List[Dict]]):
        lines = []
        for host, ports in results.items():
            for p in ports:
                lines.append(
                    f"{host}:{p['port']}/{p['protocol']}  "
                    f"{p['service']}  {p.get('version', '')}".strip()
                )
        self.executor.save_results("open_ports.txt", lines)

        json_path = self.output_dir / "open_ports.json"
        json_path.write_text(json.dumps(results, indent=2))

        total       = sum(len(p) for p in results.values())
        interesting = sum(
            1 for ports in results.values() for p in ports if p.get("interesting")
        )
        success(
            f"Port scan: {total} open ports "
            f"({interesting} interesting) across {len(results)} host(s)"
        )

    def get_interesting_ports(self, results: Dict[str, List[Dict]]) -> List[Dict]:
        """Return list of high-value open ports for AI analysis."""
        findings = []
        for host, ports in results.items():
            for p in ports:
                if p.get("interesting"):
                    findings.append({
                        "host":    host,
                        "port":    p["port"],
                        "service": p["service"],
                        "label":   p["known"],
                        "version": p.get("version", ""),
                    })
        return sorted(findings, key=lambda x: x["port"])
