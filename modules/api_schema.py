"""
ReconAI - API Schema Extraction Engine

Phase 13 — API Schema Discovery:
  Check for swagger.json, openapi.json, graphql, api-docs on every live host.
  Parse and extract all endpoint paths, methods, and parameters.
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import List, Dict
from tools.executor import ToolExecutor
from utils.logger import section, info, success, warn

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class APISchemaExtractor:
    """
    Phase 13: Probe every live host for exposed API schemas.

    Schema types detected:
    - OpenAPI / Swagger (JSON + YAML)
    - GraphQL introspection
    - API Blueprint, RAML, Postman collections
    - Custom api-docs formats

    Output: api_schema.json
    """

    # All paths to probe on each host
    SCHEMA_PATHS = [
        # Swagger / OpenAPI
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/swagger/v2/swagger.json",
        "/swagger/v3/swagger.json",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi/v1",
        "/openapi/v2",
        "/openapi/v3",
        "/api-docs",
        "/api-docs/",
        "/api-docs.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api/v1/swagger.json",
        "/api/v2/swagger.json",
        "/api/v3/swagger.json",
        "/v1/swagger.json",
        "/v2/swagger.json",
        "/v3/swagger.json",
        # ReDoc
        "/redoc",
        "/redoc/",
        "/redoc.html",
        # GraphQL
        "/graphql",
        "/graphiql",
        "/playground",
        "/api/graphql",
        "/graphql/console",
        "/graphql/playground",
        # Spring Boot Actuator
        "/actuator",
        "/actuator/",
        "/actuator/mappings",
        # Postman / generic
        "/api",
        "/api/",
        "/rest/api/2/serverInfo",     # Jira
        "/_cat/indices",              # Elasticsearch
        "/.well-known/openid-configuration",
    ]

    GRAPHQL_INTROSPECTION_QUERY = """{"query":"{__schema{types{name}}}"}"""

    def __init__(self, executor: ToolExecutor, output_dir: Path):
        self.executor   = executor
        self.output_dir = output_dir

    async def extract(self, live_hosts: List[str]) -> Dict:
        """
        Phase 13: Probe all live hosts for API schema exposure.
        Returns schema dict and saves api_schema.json.
        """
        section("Phase 13 — API Schema Extraction")

        if not live_hosts:
            warn("No live hosts — skipping API schema extraction")
            return {}

        schemas: List[Dict] = []

        import httpx as httpx_lib
        connector_limit = asyncio.Semaphore(20)   # limit concurrency

        async def probe_host(host: str):
            if not host.startswith("http"):
                host = f"https://{host}"
            host_schemas = []
            async with connector_limit:
                async with httpx_lib.AsyncClient(
                    verify=False,
                    timeout=8,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 ReconAI/2.0"}
                ) as client:
                    for path in self.SCHEMA_PATHS:
                        url = host.rstrip("/") + path
                        try:
                            resp = await client.get(url)
                            if resp.status_code not in (200, 201):
                                continue

                            content_type = resp.headers.get("content-type", "")
                            body         = resp.text[:4000]

                            schema_type, parsed = self._identify_schema(url, body, content_type)
                            if schema_type:
                                host_schemas.append({
                                    "url":         url,
                                    "host":        host,
                                    "schema_type": schema_type,
                                    "endpoints_found": len(parsed.get("paths", [])),
                                    "parsed":      parsed,
                                })
                                info(f"  Schema found: [{schema_type}] {url}")

                            # GraphQL: try introspection
                            if "graphql" in path.lower() and resp.status_code == 200:
                                gql = await self._probe_graphql(client, host.rstrip("/") + path)
                                if gql:
                                    host_schemas.append(gql)

                        except Exception:
                            continue
            return host_schemas

        all_results = await asyncio.gather(*[probe_host(h) for h in live_hosts[:30]])
        for result_list in all_results:
            schemas.extend(result_list)

        # Save
        output = {
            "total_schemas_found": len(schemas),
            "schemas": schemas,
        }
        schema_path = self.output_dir / "api_schema.json"
        schema_path.write_text(json.dumps(output, indent=2))
        success(f"Phase 13 complete: {len(schemas)} API schemas found → api_schema.json")

        # Extract all paths for endpoint dataset
        all_paths = self._extract_all_paths(schemas)
        if all_paths:
            self.executor.append_results("api_endpoints.txt", all_paths)
            info(f"  Merged {len(all_paths)} schema paths into api_endpoints.txt")

        return output

    # ──────────────────────────────────────────────────────────

    def _identify_schema(self, url: str, body: str, content_type: str):
        """Detect and parse the schema type from HTTP response."""
        body_lower = body.lower()

        # OpenAPI 3.x
        if '"openapi"' in body_lower or "openapi:" in body_lower:
            parsed = self._parse_openapi(body)
            return "openapi_3", parsed

        # Swagger 2.x
        if '"swagger"' in body_lower or "swagger:" in body_lower:
            parsed = self._parse_swagger(body)
            return "swagger_2", parsed

        # GraphQL schema response (type list)
        if "__schema" in body or "__types" in body or "GraphQL" in body:
            return "graphql_schema", {"raw": body[:500]}

        # Actuator mappings
        if "dispatcherServlets" in body or "requestMappingConditions" in body:
            return "spring_actuator_mappings", {"raw": body[:500]}

        # Generic API docs page
        if any(kw in body_lower for kw in ["api documentation", "swagger ui", "redoc"]):
            return "api_docs_page", {"url": url}

        # Elasticsearch cat/indices
        if url.endswith("/_cat/indices") and "index" in body_lower:
            return "elasticsearch_indices", {"raw": body[:500]}

        # OIDC configuration
        if "issuer" in body_lower and "token_endpoint" in body_lower:
            return "oidc_configuration", self._parse_json_safe(body)

        return None, {}

    def _parse_openapi(self, body: str) -> Dict:
        """Parse OpenAPI 3.x JSON/YAML."""
        data = self._parse_json_safe(body)
        if not data:
            return {}
        paths = list(data.get("paths", {}).keys())
        info_block = data.get("info", {})
        components = list(data.get("components", {}).get("schemas", {}).keys())
        servers    = [s.get("url", "") for s in data.get("servers", [])]
        return {
            "title":      info_block.get("title", ""),
            "version":    info_block.get("version", ""),
            "paths":      paths[:200],
            "models":     components[:50],
            "servers":    servers,
        }

    def _parse_swagger(self, body: str) -> Dict:
        """Parse Swagger 2.x JSON."""
        data = self._parse_json_safe(body)
        if not data:
            return {}
        paths   = list(data.get("paths", {}).keys())
        host    = data.get("host", "")
        base    = data.get("basePath", "/")
        schemes = data.get("schemes", ["https"])
        return {
            "title":    data.get("info", {}).get("title", ""),
            "version":  data.get("info", {}).get("version", ""),
            "host":     host,
            "basePath": base,
            "paths":    paths[:200],
            "schemes":  schemes,
        }

    async def _probe_graphql(self, client, url: str) -> Dict:
        """Send GraphQL introspection query."""
        try:
            resp = await client.post(
                url,
                content=self.GRAPHQL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = self._parse_json_safe(resp.text)
                if data and "data" in data:
                    type_names = [
                        t.get("name", "")
                        for t in data.get("data", {})
                                     .get("__schema", {})
                                     .get("types", [])
                        if not t.get("name", "").startswith("__")
                    ]
                    info(f"  GraphQL introspection succeeded: {len(type_names)} types")
                    return {
                        "url":         url,
                        "host":        url.split("/graphql")[0],
                        "schema_type": "graphql_introspection",
                        "types":       type_names[:50],
                        "endpoints_found": len(type_names),
                        "parsed":      {"types": type_names[:50]},
                    }
        except Exception:
            pass
        return {}

    def _extract_all_paths(self, schemas: List[Dict]) -> List[str]:
        """Flatten all API paths from all found schemas."""
        paths = []
        for schema in schemas:
            parsed = schema.get("parsed", {})
            schema_paths = parsed.get("paths", [])
            host         = schema.get("host", "")
            base         = parsed.get("basePath", "/")
            for p in schema_paths:
                if host:
                    paths.append(f"https://{host}{base}{p}")
                else:
                    paths.append(p)
        return list(set(paths))

    def _parse_json_safe(self, text: str) -> Dict:
        """Safely parse JSON, stripping common prefixes."""
        text = text.strip()
        # Some APIs return )]}' prefix to prevent XSSI
        for prefix in [")]}'", ")]}'\n"]:
            if text.startswith(prefix):
                text = text[len(prefix):]
        try:
            return json.loads(text)
        except Exception:
            return {}
