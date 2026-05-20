"""
OpenAPI / Swagger Spec Analyzer — Discover, parse, and analyze API specification files.
Extracts endpoints, methods, auth requirements, and identifies unauthenticated operations.

Extracted technique from Authorized reconnaissance findings:
- Found OpenAPI spec via GitHub (target/open-api)
- Parsed swagger.yml to discover 200+ API endpoints
- Identified auth requirements per endpoint
- Found public endpoints (e.g. /ai-gateway/providers with no auth)
"""

import json
import os
import re
import tempfile

import requests
import yaml


# Common paths for OpenAPI/Swagger spec files
SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api-docs",
    "/api/docs",
    "/docs/api",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/v1/openapi.json",
    "/api/v1/swagger.json",
    "/spec.json",
    "/spec.yaml",
    "/spec.yml",
]


class OpenAPIAnalyzer:
    """Discover and parse OpenAPI/Swagger specifications."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False
        self.request_delay = 0
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
        })

    def run_all(self):
        """Main entry point: discover and analyze API specs."""
        findings = {
            "spec_found": False,
            "specs": [],
            "total_endpoints": 0,
            "unauthenticated_endpoints": [],
            "sensitive_operations": [],
            "endpoints_by_category": {},
        }

        discovered = self._discover_specs()
        if not discovered:
            self.results = findings
            return self.results

        findings["spec_found"] = True
        findings["specs"] = discovered

        for spec in discovered:
            parsed = self._parse_spec(spec)
            if parsed:
                spec["parsed"] = parsed
                findings["total_endpoints"] += parsed.get("total_endpoints", 0)
                findings["unauthenticated_endpoints"].extend(
                    parsed.get("unauthenticated_endpoints", [])
                )
                findings["sensitive_operations"].extend(
                    parsed.get("sensitive_operations", [])
                )
                for category, eps in parsed.get("endpoints_by_category", {}).items():
                    findings["endpoints_by_category"].setdefault(category, [])
                    findings["endpoints_by_category"][category].extend(eps)

        # Deduplicate unauthenticated endpoints
        seen_paths = set()
        unique_unauthenticated = []
        for ep in findings["unauthenticated_endpoints"]:
            key = ep.get("path", "") + ep.get("method", "")
            if key not in seen_paths:
                seen_paths.add(key)
                unique_unauthenticated.append(ep)
        findings["unauthenticated_endpoints"] = unique_unauthenticated

        self.results = findings
        return self.results

    def _discover_specs(self):
        """Probe common paths for spec files."""
        specs = []
        paths = SPEC_PATHS
        if self.stealth:
            paths = paths[:6]

        for path in paths:
            url = f"{self.target_url}{path}"
            try:
                r = self._session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    content_type = r.headers.get("Content-Type", "")
                    content = r.text[:500].strip()
                    # Detect if it's a spec (JSON/YAML)
                    if self._looks_like_spec(content, content_type):
                        specs.append({
                            "url": url,
                            "path": path,
                            "status": r.status_code,
                            "content_type": content_type,
                            "size": len(r.content),
                            "content_preview": content[:200],
                        })
            except Exception:
                continue

        return specs

    def _looks_like_spec(self, content, content_type):
        """Heuristic: does this look like an OpenAPI spec?"""
        if not content:
            return False
        # JSON indicators
        json_hints = [
            '"openapi"', '"swagger"', '"info"', '"paths"',
            '"swaggerVersion"', '"apiVersion"',
        ]
        for hint in json_hints:
            if hint in content.lower():
                return True
        # YAML indicators
        yaml_hints = [
            "openapi:", "swagger:", "info:",
            "paths:", "components:",
        ]
        for hint in yaml_hints:
            if hint in content:
                return True
        # Content-type check
        if "json" in content_type or "yaml" in content_type or "yml" in content_type:
            return True
        return False

    def _parse_spec(self, spec_info):
        """Parse a discovered spec file."""
        url = spec_info["url"]
        try:
            r = self._session.get(url, timeout=15, verify=False)
            if r.status_code != 200:
                return None
            content = r.text
        except Exception:
            return None

        # Try JSON first, then YAML
        data = None
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            try:
                data = yaml.safe_load(content)
            except (yaml.YAMLError, Exception):
                return None

        if not data or not isinstance(data, dict):
            return None

        result = {
            "title": self._get_nested(data, "info", "title") or "Unknown",
            "version": self._get_nested(data, "info", "version") or "Unknown",
            "total_endpoints": 0,
            "endpoints": [],
            "unauthenticated_endpoints": [],
            "sensitive_operations": [],
            "endpoints_by_category": {},
        }

        # Parse paths
        paths = data.get("paths", {}) or {}
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    ep = {
                        "path": path,
                        "method": method.upper(),
                        "summary": (operation or {}).get("summary", ""),
                        "description": (operation or {}).get("description", ""),
                        "tags": (operation or {}).get("tags", []),
                        "operation_id": (operation or {}).get("operationId", ""),
                        "requires_auth": True,
                    }

                    # Check auth requirements
                    op_security = operation.get("security", [])
                    if op_security == [] or (
                        isinstance(op_security, list)
                        and all(s == {} for s in op_security)
                    ):
                        ep["requires_auth"] = False
                        ep["auth_type"] = "none"
                    elif op_security:
                        ep["auth_type"] = list(op_security[0].keys())[0] if op_security[0] else "oauth2"
                    else:
                        # Check global security
                        global_security = data.get("security", [])
                        if global_security == [] or (
                            isinstance(global_security, list)
                            and all(s == {} for s in global_security)
                        ):
                            ep["requires_auth"] = False
                            ep["auth_type"] = "none"
                        else:
                            ep["auth_type"] = "oauth2"

                    # Check for sensitive operations
                    is_sensitive = False
                    sensitive_keywords = [
                        "admin", "internal", "secret", "token", "key",
                        "password", "credential", "delete", "backup",
                        "sudo", "root", "superuser", "config",
                    ]
                    combined_text = f"{path} {method.upper()} {ep['summary']} {ep['description']}".lower()
                    if any(kw in combined_text for kw in sensitive_keywords):
                        is_sensitive = True

                    if is_sensitive:
                        ep["sensitive"] = True
                        result["sensitive_operations"].append(ep)

                    if not ep["requires_auth"]:
                        result["unauthenticated_endpoints"].append(ep)

                    if ep["tags"]:
                        for tag in ep["tags"]:
                            result["endpoints_by_category"].setdefault(tag, []).append(ep)

                    result["endpoints"].append(ep)

        result["total_endpoints"] = len(result["endpoints"])
        return result

    def _get_nested(self, data, *keys):
        """Safely retrieve nested dictionary values."""
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current

    def set_spec_content(self, yaml_content):
        """Allow direct injection of spec content (for testing or pre-fetched specs)."""
        # Not typically used in pipeline flow but available for API
        pass
