"""
CORS Deep Scanner — Origin reflection, credential+wildcard checks,
preflight analysis, and exposed method detection across multiple endpoints.

Detected production subdomain with dangerous CORS combination:
- Access-Control-Allow-Credentials: true
- Access-Control-Allow-Origin: *
- Vary: Origin
"""

import requests
import re


# Endpoints to test beyond the homepage
COMMON_CORS_TARGETS = [
    "/",
    "/api/",
    "/api/v1/",
    "/api/v1/sites",
    "/api/v1/user",
    "/graphql",
    "/health",
    "/status",
    "/.netlify/functions",
]

# Origins to test for reflection
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.net",
    "null",
    "https://{target}",
    "https://evil.{target}",
]


class CORSDeepScanner:
    """Deep CORS configuration analysis via preflight and credentialed checks."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False
        self.request_delay = 0
        self.max_workers = 5
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
        })

    def run_all(self):
        """Main entry point: run all CORS checks."""
        findings = {
            "misconfigurations": [],
            "tested_endpoints": [],
        }

        targets = self._get_targets()
        for endpoint in targets:
            endpoint_result = self._test_endpoint(endpoint)
            if endpoint_result:
                findings["tested_endpoints"].append(endpoint_result)
                if endpoint_result.get("misconfigurations"):
                    findings["misconfigurations"].extend(
                        endpoint_result["misconfigurations"]
                    )

        # Deduplicate misconfigurations
        seen = set()
        unique = []
        for m in findings["misconfigurations"]:
            key = f"{m.get('type')}:{m.get('endpoint')}"
            if key not in seen:
                seen.add(key)
                unique.append(m)
        findings["misconfigurations"] = unique
        findings["total_misconfigurations"] = len(unique)

        self.results = findings
        return self.results

    def _get_targets(self):
        """Build list of endpoints to test."""
        endpoints = ["/"]
        for ep in COMMON_CORS_TARGETS:
            if ep not in endpoints:
                endpoints.append(ep)
        if self.stealth:
            endpoints = endpoints[:3]
        return endpoints[:8]  # cap at 8

    def _test_endpoint(self, endpoint):
        """Run all CORS tests against a single endpoint."""
        url = f"{self.target_url}{endpoint}"
        result = {
            "endpoint": endpoint,
            "url": url,
            "misconfigurations": [],
        }

        # 1. Standard CORS header check (GET)
        standard = self._check_standard_cors(url)
        if standard:
            result.update(standard)
            if standard.get("cors_wildcard_credentials"):
                result["misconfigurations"].append({
                    "type": "cors_wildcard_with_credentials",
                    "severity": "CRITICAL",
                    "message": (
                        f"Access-Control-Allow-Origin: * with "
                        f"Access-Control-Allow-Credentials: true at {endpoint}. "
                        f"This allows any origin to read authenticated responses."
                    ),
                    "endpoint": endpoint,
                    "details": standard,
                })
            if standard.get("cors_wildcard_write"):
                result["misconfigurations"].append({
                    "type": "cors_wildcard_write_methods",
                    "severity": "HIGH",
                    "message": (
                        f"Wildcard CORS with write-capable methods "
                        f"({standard.get('cors_allow_methods', '')}) at {endpoint}."
                    ),
                    "endpoint": endpoint,
                    "details": standard,
                })

        # 2. Origin reflection test via OPTIONS preflight
        reflection = self._test_origin_reflection(url)
        if reflection:
            result["origin_reflection"] = reflection
            if reflection.get("reflection_detected"):
                result["misconfigurations"].append({
                    "type": "cors_origin_reflection",
                    "severity": "HIGH",
                    "message": (
                        f"Origin reflection detected at {endpoint}. "
                        f"Server echoes back the Origin header value in "
                        f"Access-Control-Allow-Origin. "
                        f"Methods: {reflection.get('methods', 'N/A')}"
                    ),
                    "endpoint": endpoint,
                    "details": reflection,
                })

        # 3. Exposed dangerous methods via OPTIONS
        methods = self._check_options_methods(url)
        if methods:
            result["options_analysis"] = methods
            if methods.get("dangerous_methods"):
                result["misconfigurations"].append({
                    "type": "dangerous_http_methods",
                    "severity": "MEDIUM",
                    "message": (
                        f"Dangerous HTTP methods enabled at {endpoint}: "
                        f"{', '.join(methods['dangerous_methods'])}. "
                        f"TRACE/PUT/DELETE may lead to XSS or data modification."
                    ),
                    "endpoint": endpoint,
                    "details": methods,
                })

        # 4. Exposed headers via CORS
        if standard and standard.get("cors_expose_headers"):
            exposed = standard["cors_expose_headers"]
            sensitive_exposed = [h for h in exposed
                                 if any(kw in h.lower()
                                        for kw in ["token", "secret", "key",
                                                   "auth", "session", "internal"])]
            if sensitive_exposed:
                result["misconfigurations"].append({
                    "type": "cors_exposed_sensitive_headers",
                    "severity": "MEDIUM",
                    "message": (
                        f"Sensitive headers exposed via Access-Control-Expose-Headers "
                        f"at {endpoint}: {', '.join(sensitive_exposed)}"
                    ),
                    "endpoint": endpoint,
                    "details": {"exposed_headers": exposed},
                })

        return result if result.get("misconfigurations") or result.get("origin_reflection") else None

    def _check_standard_cors(self, url):
        """Check standard CORS headers from a GET response."""
        try:
            r = self._session.get(url, timeout=10, verify=False)
            headers = r.headers
        except Exception:
            return None

        acao = headers.get("Access-Control-Allow-Origin", "")
        acm = headers.get("Access-Control-Allow-Methods", "")
        ach = headers.get("Access-Control-Allow-Headers", "")
        acc = headers.get("Access-Control-Allow-Credentials", "")
        aceh = headers.get("Access-Control-Expose-Headers", "")
        vary = headers.get("Vary", "")

        info = {
            "acao": acao,
            "acm": acm,
            "ach": ach,
            "acc": acc,
            "aceh": aceh,
            "vary": vary,
            "status": r.status_code,
        }

        if acao == "*":
            if acc and acc.lower() == "true":
                info["cors_wildcard_credentials"] = True
            has_dangerous = any(
                m in (acm or "").upper()
                for m in ["PUT", "POST", "PATCH", "DELETE"]
            )
            if has_dangerous:
                info["cors_wildcard_write"] = True
            info["cors_allow_methods"] = acm

        if aceh:
            info["cors_expose_headers"] = [
                h.strip() for h in aceh.split(",")
            ]

        return info

    def _test_origin_reflection(self, url):
        """Test if the server reflects the Origin header back."""
        results = {}
        for origin in TEST_ORIGINS[:3]:  # limit to first 3
            try:
                r = self._session.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                    },
                    timeout=10,
                    verify=False,
                )
                reflected = r.headers.get("Access-Control-Allow-Origin", "")
                if reflected and reflected == origin:
                    results["reflection_detected"] = True
                    results["reflected_origin"] = origin
                    results["methods"] = r.headers.get(
                        "Access-Control-Allow-Methods", ""
                    )
                    results["credentials"] = r.headers.get(
                        "Access-Control-Allow-Credentials", ""
                    )
                    break
                elif reflected and reflected != "*" and reflected.strip():
                    # Different non-wildcard origin response
                    results.setdefault("custom_origins", []).append({
                        "tested": origin,
                        "reflected": reflected,
                    })
            except Exception:
                continue

        if not results.get("reflection_detected"):
            results["reflection_detected"] = False

        return results

    def _check_options_methods(self, url):
        """Check allowed methods via OPTIONS and identify dangerous ones."""
        try:
            r = self._session.options(
                url,
                timeout=10,
                verify=False,
            )
            allow = r.headers.get("Allow", "")
            if not allow:
                allow = r.headers.get("Access-Control-Allow-Methods", "")
            if not allow:
                return None
            methods = [m.strip().upper() for m in allow.split(",")]
            dangerous = [
                m for m in methods
                if m in ("TRACE", "PUT", "DELETE", "PATCH", "CONNECT")
            ]
            return {
                "allowed_methods": methods,
                "dangerous_methods": dangerous,
                "has_dangerous": bool(dangerous),
            }
        except Exception:
            return None
