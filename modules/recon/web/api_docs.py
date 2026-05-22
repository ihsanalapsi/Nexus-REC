"""
API Documentation Discovery — Discover and parse API documentation pages.

Extracted technique from Authorized reconnaissance findings:
- ASP.NET Web API Help page (/help) exposed 164 API endpoints
- All controllers, actions, methods, and parameters were fully documented
- 30+ endpoints were unauthenticated

This module discovers and parses:
- ASP.NET Web API Help Pages (/help, /help/api, /help/v1)
- Generic API documentation pages (/docs, /api/docs)
- Extracts endpoints, HTTP methods, parameters, and auth requirements
"""

import re
import concurrent.futures
from urllib.parse import urljoin, urlparse

import requests


COMMON_DOC_PATHS = [
    # ASP.NET Web API Help Pages
    "/help",
    "/help/api",
    "/help/v1",
    "/help/v2",
    "/en/help",
    "/ar/help",
    # Generic documentation
    "/docs",
    "/api/docs",
    "/documentation",
    "/api/documentation",
    "/developer",
    "/api/developer",
]


class APIDocsRecon:
    """Discover and parse API documentation pages."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False
        self.max_workers = 5
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0"})

    def _request(self, url, timeout=8):
        try:
            return self._session.get(url, timeout=timeout, verify=False)
        except requests.exceptions.SSLError:
            try:
                http_url = url.replace("https://", "http://")
                return self._session.get(http_url, timeout=timeout, verify=False)
            except Exception:
                return None
        except Exception:
            return None

    def discover_doc_pages(self):
        """Find API documentation pages on the target."""
        findings = []

        def _check(path):
            url = urljoin(self.target_url, path)
            r = self._request(url, timeout=6)
            if r and r.status_code == 200 and len(r.content) > 500:
                content_type = r.headers.get("Content-Type", "").lower()
                html = r.text.lower()
                # Must be HTML with API-related content
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return None
                api_signals = [
                    "api", "endpoint", "controller", "method", "request",
                    "response", "parameter", "uri", "resource",
                ]
                signal_count = sum(1 for sig in api_signals if sig in html)
                if signal_count < 2:
                    return None
                return {
                    "path": path,
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "signal_count": signal_count,
                    "content_type": content_type,
                }
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(COMMON_DOC_PATHS))
        ) as ex:
            futures = [ex.submit(_check, p) for p in COMMON_DOC_PATHS]
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    findings.append(result)

        findings.sort(key=lambda x: x["signal_count"], reverse=True)
        self.results["doc_pages"] = findings
        return findings

    def parse_aspnet_help_page(self, url):
        """Parse ASP.NET Web API Help Page HTML to extract endpoints."""
        findings = {
            "controllers": [],
            "total_endpoints": 0,
            "unauthenticated_endpoints": 0,
        }
        r = self._request(url)
        if not r or r.status_code != 200:
            return findings

        html = r.text
        soup_lower = html.lower()

        # Detect ASP.NET Help Page
        is_aspnet = any(sig in soup_lower for sig in [
            "asp.net web api", "help page", "microsoft help",
            "apidescription", "apidescription",
        ])
        if not is_aspnet:
            return findings

        # Extract API endpoint groups/categories
        # ASP.NET Help pages use <h2> for controller groups and tables for endpoints
        controller_sections = re.findall(
            r'<h2[^>]*>(.*?)</h2>',
            html,
            re.IGNORECASE | re.DOTALL,
        )

        # More precise: find all API endpoint URIs in the help page
        # Pattern: /api/ControllerName or /ControllerName (GET/POST/PUT/DELETE)
        api_patterns = re.findall(
            r'<a[^>]*href="([^"]*/(?:api|account|token|reset|send|upload|student|agent|service|university|major|blog|country|employee|subscribe|video|file)[^"]*)"[^>]*>',
            html,
            re.IGNORECASE,
        )

        # Extract from tables (ASP.NET Help format)
        # Each <tr> often contains an API endpoint with method badge
        rows = re.findall(
            r'<tr>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?</tr>',
            html,
            re.IGNORECASE | re.DOTALL,
        )

        extracted_endpoints = []
        seen_uris = set()

        for row in rows:
            method = re.sub(r'<[^>]+>', '', row[0]).strip()
            uri = re.sub(r'<[^>]+>', '', row[1]).strip()
            description = re.sub(r'<[^>]+>', '', row[2]).strip() if len(row) > 2 else ""

            if uri and uri not in seen_uris:
                seen_uris.add(uri)
                extracted_endpoints.append({
                    "uri": uri,
                    "method": method.upper() if method else "GET",
                    "description": description[:200],
                    "source": "aspnet_help_table",
                })

        # Also extract from links/anchors
        for path in api_patterns:
            if path not in seen_uris:
                seen_uris.add(path)
                method = "GET"  # default if not specified
                extracted_endpoints.append({
                    "uri": path,
                    "method": method,
                    "description": "",
                    "source": "aspnet_help_link",
                })

        # Extract API description blocks (each API method is described in a section)
        # Pattern: <div class="api-documentation"> or similar
        api_blocks = re.findall(
            r'<div[^>]*class="[^"]*api[^"]*documentation[^"]*"[^>]*>.*?</div>',
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if not api_blocks:
            # Fallback: try to find API method sections
            api_blocks = re.findall(
                r'<div[^>]*class="[^"]*(?:method|endpoint|api)[^"]*"[^>]*>.*?</div>',
                html,
                re.IGNORECASE | re.DOTALL,
            )

        for block in api_blocks:
            # Extract HTTP method badge (GET, POST, PUT, DELETE, PATCH)
            method_match = re.search(
                r'<span[^>]*class="[^"]*(?:get|post|put|delete|patch|http)[^"]*"[^>]*>\s*(GET|POST|PUT|DELETE|PATCH)\s*</span>',
                block,
                re.IGNORECASE,
            )
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract URI
            uri_match = re.search(
                r'<a[^>]*href="([^"]+)"[^>]*>([^<]+)</a>',
                block,
            )
            if uri_match:
                uri = uri_match.group(2).strip()
            else:
                uri_match = re.search(r'<code[^>]*>(/?(?:api|account|token|reset)[^<]*)</code>', block, re.IGNORECASE)
                uri = uri_match.group(1).strip() if uri_match else ""

            if uri and uri not in seen_uris:
                seen_uris.add(uri)
                # Extract description
                desc_match = re.search(
                    r'<p[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)</p>',
                    block,
                    re.IGNORECASE | re.DOTALL,
                )
                description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip() if desc_match else ""
                extracted_endpoints.append({
                    "uri": uri,
                    "method": method,
                    "description": description[:200],
                    "source": "aspnet_help_block",
                })

        # Deduplicate by URI
        unique_endpoints = []
        seen_uris_clean = set()
        for ep in extracted_endpoints:
            clean_uri = ep["uri"].split("?")[0].rstrip("/")
            if clean_uri and clean_uri not in seen_uris_clean:
                seen_uris_clean.add(clean_uri)
                unique_endpoints.append(ep)

        # Identify unauthenticated endpoints (based on common patterns)
        no_auth_keywords = [
            "no authentication", "anonymous", "public", "allow anonymous",
            "no authorization", "not secured",
        ]
        auth_required_keywords = [
            "authorization", "authentication", "requires auth", "token required",
            "bearer", "secured", "login required",
        ]

        unauth_count = 0
        for ep in unique_endpoints:
            desc_lower = ep["description"].lower()
            uri_lower = ep["uri"].lower()

            # Check description for auth clues
            if any(kw in desc_lower for kw in auth_required_keywords):
                ep["auth_required"] = True
            elif any(kw in desc_lower for kw in no_auth_keywords):
                ep["auth_required"] = False
                unauth_count += 1
            else:
                # Default: check if it's a sensitive path
                sensitive = any(p in uri_lower for p in [
                    "login", "register", "token", "password", "forgot",
                    "reset", "account",
                ])
                ep["auth_required"] = None  # unknown
                if not sensitive:
                    unauth_count += 1

        endpoints_by_controller = {}
        for ep in unique_endpoints:
            uri = ep["uri"]
            parts = uri.strip("/").split("/")
            controller = parts[1] if len(parts) > 1 and parts[0] in ("api", "v1", "v2") else parts[0]
            controller = controller.split("?")[0]
            endpoints_by_controller.setdefault(controller, []).append(ep)

        findings = {
            "is_aspnet_help": True,
            "controllers": list(endpoints_by_controller.keys()),
            "controllers_detail": {
                ctrl: {
                    "endpoint_count": len(eps),
                    "endpoints": eps[:20],  # limit per controller
                    "total_for_controller": len(eps),
                }
                for ctrl, eps in sorted(endpoints_by_controller.items())
            },
            "total_endpoints": len(unique_endpoints),
            "unauthenticated_endpoints": unauth_count,
            "endpoints": unique_endpoints,
        }
        return findings

    def parse_generic_docs(self, url):
        """Parse generic API documentation pages."""
        findings = {
            "endpoints": [],
            "total_endpoints": 0,
            "source": "generic_docs",
        }
        r = self._request(url)
        if not r or r.status_code != 200:
            return findings

        html = r.text
        # Extract all links that look like API endpoints
        api_link_pattern = re.findall(
            r'href="(/?[^"]*(?:api|v[0-9]+|rest|graphql|endpoint)[^"]*)"',
            html,
            re.IGNORECASE,
        )
        seen = set()
        for link in api_link_pattern:
            clean = link.split("?")[0].rstrip("/")
            if clean and clean not in seen and len(clean) > 2:
                seen.add(clean)
                findings["endpoints"].append(clean)

        findings["total_endpoints"] = len(findings["endpoints"])
        return findings

    def run_all(self):
        """Run all API documentation discovery checks."""
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.results = {}

        # Step 1: Discover doc pages
        doc_pages = self.discover_doc_pages()
        self.results["doc_pages_discovered"] = len(doc_pages)

        if doc_pages:
            self.results["doc_pages"] = doc_pages

            # Step 2: Parse each doc page
            all_endpoints = []
            aspnet_help_found = False

            for page in doc_pages:
                url = page["url"]
                path = page["path"].lower()

                # Try ASP.NET Help Page parsing first
                aspnet_result = self.parse_aspnet_help_page(url)
                if aspnet_result.get("is_aspnet_help") and aspnet_result["total_endpoints"] > 0:
                    aspnet_help_found = True
                    self.results["aspnet_help"] = aspnet_result
                    all_endpoints.extend(aspnet_result.get("endpoints", []))
                else:
                    # Fall back to generic parsing
                    generic_result = self.parse_generic_docs(url)
                    if generic_result["total_endpoints"] > 0:
                        all_endpoints.extend(generic_result["endpoints"])

            self.results["total_endpoints_found"] = len(all_endpoints)
            self.results["endpoints"] = all_endpoints[:200]  # cap at 200

            if aspnet_help_found:
                self.results["help_type"] = "aspnet_web_api"
            else:
                self.results["help_type"] = "generic"

        return self.results
