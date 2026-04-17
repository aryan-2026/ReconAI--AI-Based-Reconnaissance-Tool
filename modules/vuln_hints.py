"""
ReconAI - Vulnerability Hint Engine
Automated rule-based analysis of all collected recon data.
Produces prioritized, actionable hints for the pentester.
"""
import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from utils.logger import section, info, success, warn, console
from core.config import PRIORITY_KEYWORDS


class VulnHintEngine:
    """
    Scans all recon data for vulnerability indicators.
    Rules cover: open ports, web technologies, endpoints,
    cloud assets, JS secrets, and tech-specific CVEs.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    # ─────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────

    def analyze(self, recon_data: dict) -> List[Dict]:
        section("Vulnerability Hint Engine")
        hints: List[Dict] = []

        for host in recon_data.get("live_hosts", []):
            if isinstance(host, dict):
                hints.extend(self._analyze_host(host))

        for host, ports in (recon_data.get("open_ports") or {}).items():
            if isinstance(ports, list):
                hints.extend(self._analyze_ports(host, ports))

        for endpoint in recon_data.get("endpoints", []):
            hints.extend(self._analyze_endpoint(str(endpoint)))

        for asset in recon_data.get("cloud_assets", []):
            if isinstance(asset, dict):
                hints.extend(self._analyze_cloud_asset(asset))

        for secret in recon_data.get("js_secrets", []):
            if isinstance(secret, dict):
                hints.append(self._hint(
                    secret.get("source_url", "unknown"),
                    "EXPOSED_SECRET",
                    f"Potential {secret.get('type', 'secret')} found in JavaScript: "
                    f"{secret.get('value', '')[:50]}",
                    10
                ))

        hints.extend(self._analyze_technologies(recon_data))

        # Deduplicate on (target, hint_type)
        seen = set()
        unique_hints = []
        for h in hints:
            key = (h.get("target", ""), h.get("hint_type", ""))
            if key not in seen:
                seen.add(key)
                unique_hints.append(h)

        unique_hints.sort(key=lambda h: h.get("score", 0), reverse=True)
        self._save_hints(unique_hints)
        success(f"Generated {len(unique_hints)} vulnerability hints")
        return unique_hints

    # ─────────────────────────────────────────────────────────
    # Host / service analysis
    # ─────────────────────────────────────────────────────────

    def _analyze_host(self, host: Dict) -> List[Dict]:
        hints = []
        url      = host.get("url",      "")
        title    = host.get("title",    "").lower()
        techs    = [t.lower() for t in host.get("technologies", [])]
        category = host.get("category", "")
        server   = host.get("server",   "").lower()
        waf      = host.get("waf",      "").lower()
        combined = f"{url.lower()} {title} {' '.join(techs)} {server}"

        if not url:
            return hints

        # ── Service category hints ────────────────────────────
        cat_hints = {
            "login_panel":       (9,  "LOGIN_PORTAL",
                "Test credential stuffing, brute force, default creds, MFA bypass, SQLi"),
            "admin_dashboard":   (10, "ADMIN_PANEL",
                "Test auth bypass, default credentials, privilege escalation, IDOR"),
            "dev_environment":   (8,  "DEV_ENVIRONMENT",
                "Dev env — debug mode likely, weak auth, verbose errors, test data"),
            "monitoring_system": (8,  "MONITORING_EXPOSED",
                "Monitoring exposed — topology leak, credential exposure, SSRF pivot"),
            "file_upload":       (9,  "FILE_UPLOAD",
                "Test unrestricted upload, path traversal, MIME bypass, webshell upload"),
            "api_service":       (7,  "API_SURFACE",
                "API exposed — test auth, rate limiting, mass assignment, IDOR, injection"),
        }
        if category in cat_hints:
            score, htype, reason = cat_hints[category]
            hints.append(self._hint(url, htype, reason, score))

        # ── Technology-specific hints ─────────────────────────
        tech_map = [
            (["wordpress"],      9,  "WORDPRESS",      "wpscan: plugins, themes, user enum, CVEs"),
            (["drupal"],         8,  "DRUPAL",         "Check Drupalgeddon2/3, REST API, admin bypass"),
            (["joomla"],         8,  "JOOMLA",         "Joomla! — check extensions, brute force /administrator"),
            (["jenkins"],        9,  "JENKINS",        "Jenkins — anon access, script console RCE, CVE-2024-23897"),
            (["kibana"],         9,  "KIBANA",         "Kibana — unauth access, SSRF, prototype pollution, RCE"),
            (["grafana"],        8,  "GRAFANA",        "Grafana — CVE-2021-43798 path traversal, default admin:admin"),
            (["phpmyadmin"],     9,  "PHPMYADMIN",     "phpMyAdmin — default creds, SQL injection, CVEs"),
            (["elasticsearch"],  10, "ELASTICSEARCH",  "Elasticsearch — likely unauthenticated, full data access"),
            (["mongodb"],        10, "MONGODB",        "MongoDB — check for noauth, list all databases"),
            (["redis"],          10, "REDIS",          "Redis open — likely no auth, RCE via config write"),
            (["struts"],         9,  "APACHE_STRUTS",  "Apache Struts — OGNL injection CVEs (CVE-2023-50164)"),
            (["spring"],         8,  "SPRING",         "Spring — Spring4Shell CVE-2022-22965, actuator exposure"),
            (["laravel"],        7,  "LARAVEL",        "Laravel — .env exposure, debug mode RCE, mass assignment"),
            (["rails"],          7,  "RAILS",          "Rails — check secret_key_base leaks, mass assignment, CVEs"),
            (["tomcat"],         8,  "TOMCAT",         "Tomcat — /manager brute force, CVE-2025-24813 partial PUT"),
            (["iis"],            7,  "IIS",            "IIS — check WebDAV, PUT method, short filename disclosure"),
            (["nginx"],          5,  "NGINX",          "Nginx — check off-by-slash alias traversal, open proxy"),
            (["apache"],         5,  "APACHE",         "Apache — check mod_status, .htaccess exposure, CVEs"),
            (["node", "nodejs"], 6,  "NODEJS",         "Node.js — prototype pollution, path traversal, SSRF"),
            (["next.js"],        6,  "NEXTJS",         "Next.js — CVE-2025-29927 middleware auth bypass"),
            (["django"],         6,  "DJANGO",         "Django — DEBUG mode, admin/admin, secret key leak"),
            (["flask"],          6,  "FLASK",          "Flask — debug console PIN brute, SSTI, secret key"),
        ]

        for tech_keys, score, htype, reason in tech_map:
            if any(tk in combined for tk in tech_keys):
                hints.append(self._hint(url, htype, reason, score))

        # ── Server version hints ──────────────────────────────
        if re.search(r"apache/2\.[01]\.", server):
            hints.append(self._hint(url, "OLD_APACHE", "Apache 2.0/2.1 EOL — many unpatched CVEs", 8))
        if re.search(r"nginx/1\.[0-9]\.", server):
            hints.append(self._hint(url, "OLD_NGINX", "Old Nginx — check for known CVEs", 6))
        if re.search(r"php/[45]\.", server):
            hints.append(self._hint(url, "OLD_PHP", "PHP 4/5 EOL — numerous RCE/injection vulnerabilities", 9))
        if re.search(r"iis/[456789]\.", server):
            hints.append(self._hint(url, "OLD_IIS", "Old IIS version — CVE exposure, WebDAV risks", 7))

        # ── WAF-bypass opportunity ────────────────────────────
        if waf:
            hints.append(self._hint(url, "WAF_DETECTED",
                f"WAF detected ({waf}) — attempt bypass: case variation, encoding, fragmentation", 5))

        # ── Generic checks for every host ─────────────────────
        hints.append(self._hint(url, "CORS_CHECK",
            "Probe for CORS misconfig: Origin: evil.com — check ACAO header", 5))
        hints.append(self._hint(url, "CLICKJACKING",
            "Check for missing X-Frame-Options / CSP frame-ancestors", 4))
        hints.append(self._hint(url, "SECURITY_HEADERS",
            "Audit security headers: HSTS, CSP, X-Content-Type-Options, Referrer-Policy", 4))

        return hints

    # ─────────────────────────────────────────────────────────
    # Port analysis
    # ─────────────────────────────────────────────────────────

    def _analyze_ports(self, host: str, ports: List[Dict]) -> List[Dict]:
        hints = []
        port_map = {p["port"]: p for p in ports if isinstance(p, dict)}

        rules = {
            21:    (7,  "FTP_OPEN",          "FTP — test anonymous login, clear-text creds, bounce attack"),
            22:    (5,  "SSH_OPEN",           "SSH — check old versions, weak keys, brute force"),
            23:    (9,  "TELNET_OPEN",        "Telnet open — clear-text protocol, credential sniffing"),
            25:    (6,  "SMTP_OPEN",          "SMTP — test open relay, VRFY/EXPN user enum"),
            445:   (8,  "SMB_OPEN",           "SMB — EternalBlue, null sessions, relay attacks"),
            1433:  (9,  "MSSQL_EXPOSED",      "MSSQL exposed — default sa, xp_cmdshell RCE"),
            1521:  (8,  "ORACLE_EXPOSED",     "Oracle DB exposed — default accounts, TNS poison"),
            2375:  (10, "DOCKER_EXPOSED",     "Docker API UNAUTHENTICATED — container escape to host RCE"),
            2376:  (8,  "DOCKER_TLS",         "Docker TLS API — verify cert validation, container escape"),
            3306:  (9,  "MYSQL_EXPOSED",      "MySQL exposed — test blank/default root password"),
            3389:  (8,  "RDP_OPEN",           "RDP open — BlueKeep, NLA bypass, brute force"),
            5432:  (8,  "POSTGRES_EXPOSED",   "PostgreSQL exposed — default postgres/postgres, COPY TO/FROM"),
            5900:  (8,  "VNC_OPEN",           "VNC open — test no-auth, default passwords"),
            6379:  (10, "REDIS_EXPOSED",      "Redis open — almost certainly no auth, RCE via config write"),
            6443:  (9,  "K8S_API_EXPOSED",    "Kubernetes API — anonymous access, privilege escalation"),
            9200:  (10, "ELASTICSEARCH_OPEN", "Elasticsearch open — unauthenticated, dump all indices"),
            10250: (9,  "KUBELET_EXPOSED",    "Kubelet API — exec in pods, token extraction"),
            27017: (10, "MONGODB_OPEN",       "MongoDB open — test noauth, list all databases"),
            50000: (9,  "JENKINS_PORT",       "Jenkins HTTP — anonymous access, script console RCE"),
        }

        for port_num, (score, htype, reason) in rules.items():
            if port_num in port_map:
                hints.append(self._hint(f"{host}:{port_num}", htype, reason, score))

        return hints

    # ─────────────────────────────────────────────────────────
    # Endpoint analysis
    # ─────────────────────────────────────────────────────────

    def _analyze_endpoint(self, endpoint: str) -> List[Dict]:
        hints = []
        ep = endpoint.lower()

        checks = [
            (r"\.(bak|old|backup|copy|orig|save|swp|tmp)($|\?|#)",
             "BACKUP_FILE", "Backup file — may contain source code or credentials", 9),

            (r"(^|/)\.git(/|$)",
             "GIT_EXPOSURE", "Git repo exposed — dump with git-dumper to extract source", 10),

            (r"(^|/)\.svn(/|$)|/cvs/",
             "VCS_EXPOSURE", "SVN/CVS directory exposed — extract source code", 9),

            (r"(^|/)\.(env|env\.local|env\.prod|env\.dev)($|\?)",
             "ENV_FILE", ".env file exposed — likely contains DB creds, API keys, secrets", 10),

            (r"(config|settings|app)\.(json|yaml|yml|xml|ini|php|py)($|\?)",
             "CONFIG_FILE", "Config file exposed — check for credentials and secrets", 9),

            (r"\?.*[?&](id|user_?id|uid|account)=\d+",
             "IDOR_PARAM", "Numeric ID parameter — test IDOR/access control bypasses", 8),

            (r"\?.*[?&](file|path|dir|url|src|dest|redirect|next|return|callback)=",
             "TRAVERSAL_PARAM", "File/path parameter — test path traversal, LFI, SSRF, open redirect", 9),

            (r"/(upload|file-upload|fileupload|attach|media/upload)",
             "UPLOAD_ENDPOINT", "Upload endpoint — test unrestricted upload, path traversal, zip slip", 9),

            (r"/(admin|administrator|wp-admin|controlpanel|cpanel|panel)",
             "ADMIN_PATH", "Admin path found — test auth bypass, default credentials", 9),

            (r"/(phpmyadmin|pma|mysqladmin|adminer|dbadmin)",
             "DB_ADMIN_UI", "Database admin UI exposed — brute force, SQLi, default creds", 9),

            (r"/(actuator|actuator/|spring/|/health|/env|/metrics|/heapdump|/httptrace)",
             "SPRING_ACTUATOR", "Spring Boot Actuator — /env may expose secrets, /heapdump = memory dump", 9),

            (r"/(graphql|graphiql|playground|api/graphql)",
             "GRAPHQL_ENDPOINT", "GraphQL — introspection, batch attack, nested query DoS, auth bypass", 8),

            (r"/(swagger|swagger-ui|api-docs|openapi|redoc|apidoc)",
             "API_DOCS_EXPOSED", "API docs exposed — enumerate all endpoints, test each for auth/injection", 8),

            (r"(console|debug|test|phpinfo\.php|info\.php|server-status|server-info)",
             "DEBUG_PAGE", "Debug/info page — may expose server internals, config, credentials", 9),
        ]

        for pattern, htype, reason, score in checks:
            if re.search(pattern, ep):
                hints.append(self._hint(endpoint, htype, reason, score))

        return hints

    # ─────────────────────────────────────────────────────────
    # Cloud asset analysis
    # ─────────────────────────────────────────────────────────

    def _analyze_cloud_asset(self, asset: Dict) -> List[Dict]:
        hints = []
        url      = asset.get("url", "")
        status   = asset.get("status", "")
        provider = asset.get("provider", "")

        if "PUBLIC" in status:
            hints.append(self._hint(url, "PUBLIC_CLOUD_STORAGE",
                f"Publicly readable {provider} storage — list/download all objects, "
                "check for secrets/backups/source code", 10))
        elif "EXISTS" in status or "PROTECTED" in status:
            hints.append(self._hint(url, "CLOUD_ASSET_EXISTS",
                f"{provider} asset exists ({status}) — test read/write/delete permissions, "
                "bucket takeover if DNS points here", 7))

        if "firebase" in url.lower() and "PUBLIC" in status:
            hints.append(self._hint(url, "FIREBASE_OPEN",
                "Firebase database publicly readable/writable — full data access, "
                "potential write access for stored-XSS", 10))

        return hints

    # ─────────────────────────────────────────────────────────
    # Technology-level analysis across all hosts
    # ─────────────────────────────────────────────────────────

    def _analyze_technologies(self, recon_data: dict) -> List[Dict]:
        hints = []
        all_tech_str = json.dumps(recon_data.get("live_hosts", [])).lower()

        global_checks = [
            ("log4j",      10, "LOG4J_POSSIBLE",
             "Log4j detected — test CVE-2021-44228 (Log4Shell) JNDI injection"),
            ("solr",       9,  "SOLR_EXPOSED",
             "Apache Solr — test CVE-2019-0193 DataImportHandler RCE, unauthenticated access"),
            ("confluence", 9,  "CONFLUENCE",
             "Confluence — CVE-2023-22515 broken access, CVE-2022-26134 OGNL injection"),
            ("gitlab",     8,  "GITLAB",
             "GitLab — CVE-2021-22205 RCE, user enumeration, private repo access"),
            ("mattermost", 7,  "MATTERMOST",
             "Mattermost — test for unauthenticated API, user enumeration"),
            ("roundcube",  7,  "ROUNDCUBE",
             "Roundcube webmail — CVE-2023-43770 XSS/RCE, brute force"),
        ]

        for tech, score, htype, reason in global_checks:
            if tech in all_tech_str:
                hints.append(self._hint("(global)", htype, reason, score))

        return hints

    # ─────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────

    def _hint(self, target: str, hint_type: str, reason: str, score: int) -> Dict:
        priority = (
            "CRITICAL" if score >= 9 else
            "HIGH"     if score >= 7 else
            "MEDIUM"   if score >= 5 else
            "LOW"
        )
        return {
            "target":    target,
            "hint_type": hint_type,
            "reason":    reason,
            "priority":  priority,
            "score":     score,
        }

    def _save_hints(self, hints: List[Dict]):
        json_path = self.output_dir / "vulnerability_hints.json"
        json_path.write_text(json.dumps(hints, indent=2))

        critical = [h for h in hints if h["priority"] == "CRITICAL"]
        high     = [h for h in hints if h["priority"] == "HIGH"]

        if critical:
            console.print(f"\n[bold red]  🚨 CRITICAL ({len(critical)}):[/bold red]")
            for h in critical[:8]:
                console.print(f"  [red]  ▶ [{h['hint_type']}] {str(h['target'])[:70]}[/red]")
                console.print(f"  [dim]    {h['reason'][:90]}[/dim]")
        if high:
            console.print(f"\n[bold yellow]  ⚠ HIGH ({len(high)}):[/bold yellow]")
            for h in high[:6]:
                console.print(f"  [yellow]  ▶ [{h['hint_type']}] {str(h['target'])[:70]}[/yellow]")
