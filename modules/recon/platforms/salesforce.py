"""
Salesforce Recon — Detect and enumerate Salesforce instances.
"""

import concurrent.futures
import re

import requests


# Common Salesforce subdomains
SALESFORCE_SUBDOMAINS = [
    "login", "test", "developer", "trailblazer", "help",
    "success", "partners", "trust", "admin", "api",
]

# Salesforce API versions to check
SALESFORCE_API_VERSIONS = [
    "57.0", "58.0", "59.0", "60.0", "61.0",
    "56.0", "55.0", "54.0", "53.0", "52.0",
    "51.0", "50.0",
]

# Common Salesforce endpoints
SALESFORCE_ENDPOINTS = [
    "/services/data",
    "/services/oauth2/token",
    "/services/oauth2/authorize",
    "/services/Soap/u",
    "/services/Soap/c",
    "/services/apexrest",
    "/services/async",
    "/services/streaming",
]

# Salesforce instance patterns
SALESFORCE_INSTANCE_PATTERNS = [
    r"\.salesforce\.com",
    r"\.force\.com",
    r"\.cloudforce\.com",
    r"salesforce[-_]",
    r"my\.salesforce\.com",
    r"login\.salesforce\.com",
]


class SalesforceRecon:
    """Detect and enumerate Salesforce instances."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False
        self.max_workers = 8
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

    def detect_salesforce_headers(self):
        """Detect Salesforce from HTTP response headers."""
        findings = {"headers_found": {}, "detected": False}
        r = self._request(self.target_url)
        if not r:
            self.results["header_detection"] = findings
            return findings

        for key, value in r.headers.items():
            key_lower = key.lower()
            value_lower = value.lower()
            if "salesforce" in value_lower or "force.com" in value_lower:
                findings["headers_found"][key] = value
                findings["detected"] = True
            if key_lower in ("x-salesforce", "x-force"):
                findings["headers_found"][key] = value
                findings["detected"] = True

        self.results["header_detection"] = findings
        return findings

    def detect_salesforce_from_html(self):
        """Detect Salesforce references in HTML content."""
        findings = {"detected": False, "indicators": []}
        r = self._request(self.target_url)
        if not r or not r.text:
            self.results["html_detection"] = findings
            return findings

        html_lower = r.text.lower()
        indicators = [
            "salesforce", "force.com", "salesforce.com",
            "sfdc", "visualforce", "apex", "soql",
            "sosl", "scontrol", "lightning",
            "__sfdcSessionId",
        ]
        for ind in indicators:
            if ind in html_lower:
                findings["indicators"].append(ind)
                findings["detected"] = True

        self.results["html_detection"] = findings
        return findings

    def probe_salesforce_subdomains(self):
        """Probe common Salesforce subdomains."""
        findings = {"subdomains": []}
        base_domain = ".".join(self.domain.split(".")[-2:])  # example.com

        def _check_sub(sub):
            fqdn = f"{sub}.{base_domain}"
            try:
                url = f"https://{fqdn}"
                r = self._request(url, timeout=5)
                if r:
                    html_lower = r.text.lower()
                    is_salesforce = (
                        "salesforce" in html_lower
                        or "force.com" in html_lower
                        or "visualforce" in html_lower
                        or "lightning" in html_lower
                        or "apex" in html_lower
                    )
                    return {
                        "subdomain": fqdn,
                        "status": r.status_code,
                        "size": len(r.content),
                        "is_salesforce": is_salesforce,
                        "server": r.headers.get("Server", ""),
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(SALESFORCE_SUBDOMAINS))
        ) as ex:
            for r in ex.map(_check_sub, SALESFORCE_SUBDOMAINS):
                if r:
                    findings["subdomains"].append(r)

        sf_found = [s for s in findings["subdomains"] if s.get("is_salesforce")]
        findings["count"] = len(findings["subdomains"])
        findings["salesforce_count"] = len(sf_found)

        self.results["subdomains"] = findings
        return findings

    def check_salesforce_instances(self):
        """Check for Salesforce cloud instances (not subdomains)."""
        findings = {"instances": []}

        # Check common Salesforce instance URLs
        instance_base = self.domain.replace("-dev-ed", "").replace("-sandbox", "")
        instance_urls = [
            f"https://{instance_base}.my.salesforce.com",
            f"https://{instance_base}.salesforce.com",
            f"https://{instance_base}.develop.my.salesforce.com",
            f"https://{instance_base}.sandbox.my.salesforce.com",
            f"https://cs{abs(hash(instance_base) % 100):d}.salesforce.com",
        ]

        def _check_instance(url):
            try:
                r = self._request(url, timeout=5)
                if r:
                    html = r.text.lower()
                    if any(sig in html for sig in ["salesforce", "login", "username", "password"]):
                        return {
                            "url": url,
                            "status": r.status_code,
                            "detected": True,
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(instance_urls))
        ) as ex:
            for r in ex.map(_check_instance, instance_urls):
                if r:
                    findings["instances"].append(r)

        self.results["instances"] = findings
        return findings

    def enumerate_api_versions(self):
        """Enumerate Salesforce API versions."""
        findings = {"versions": []}

        # Try on the main domain
        for version in SALESFORCE_API_VERSIONS[:5]:  # limit to latest 5
            url = f"https://{self.domain}/services/data/v{version}/"
            r = self._request(url, timeout=5)
            if r:
                findings["versions"].append({
                    "version": version,
                    "url": url,
                    "status": r.status_code,
                    "response_preview": r.text[:200] if r.text else "",
                })

        # Try on known Salesforce patterns from subdomains
        sf_subs = self.results.get("subdomains", {}).get("subdomains", [])
        for sub_info in sf_subs:
            if sub_info.get("is_salesforce") and sub_info.get("status") == 200:
                for version in SALESFORCE_API_VERSIONS[:3]:
                    url = f"https://{sub_info['subdomain']}/services/data/v{version}/"
                    r = self._request(url, timeout=5)
                    if r and r.status_code != 404:
                        findings["versions"].append({
                            "version": version,
                            "url": url,
                            "status": r.status_code,
                            "response_preview": r.text[:200] if r.text else "",
                            "source": sub_info["subdomain"],
                        })

        # Deduplicate
        seen_versions = set()
        unique_versions = []
        for v in findings["versions"]:
            key = (v.get("url", ""), v.get("version", ""))
            if key not in seen_versions:
                seen_versions.add(key)
                unique_versions.append(v)
        findings["versions"] = unique_versions
        findings["version_count"] = len(unique_versions)

        self.results["api_versions"] = findings
        return findings

    def check_unauthenticated_endpoints(self):
        """Check for unauthenticated access to Salesforce endpoints."""
        findings = {"accessible_endpoints": []}

        targets = [
            f"https://{self.domain}{ep}"
            for ep in SALESFORCE_ENDPOINTS
        ]

        # Also try from discovered Salesforce subdomains
        sf_subs = self.results.get("subdomains", {}).get("subdomains", [])
        for sub_info in sf_subs:
            if sub_info.get("is_salesforce"):
                for ep in SALESFORCE_ENDPOINTS[:3]:  # limit
                    targets.append(f"https://{sub_info['subdomain']}{ep}")

        def _check_ep(url):
            r = self._request(url, timeout=5)
            if r:
                return {
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "content_type": r.headers.get("Content-Type", ""),
                }
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(targets))
        ) as ex:
            for r in ex.map(_check_ep, targets):
                if r and r["status"] not in (404, 405):
                    # Non-404 response means something is there
                    if r["status"] in (200, 401, 403, 302, 301):
                        findings["accessible_endpoints"].append(r)

        findings["total_accessible"] = len(findings["accessible_endpoints"])
        self.results["unauth_endpoints"] = findings
        return findings

    def run_all(self):
        """Run all Salesforce recon checks."""
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.results = {}

        # Detect via headers
        self.detect_salesforce_headers()
        header_detected = self.results.get("header_detection", {}).get("detected", False)

        # Detect via HTML
        self.detect_salesforce_from_html()
        html_detected = self.results.get("html_detection", {}).get("detected", False)

        if header_detected or html_detected:
            self.results["detected"] = True
            # Probe deeper only if Salesforce was detected
            self.probe_salesforce_subdomains()
            self.check_salesforce_instances()
            self.enumerate_api_versions()
            self.check_unauthenticated_endpoints()
        else:
            self.results["detected"] = False
            # Light probe even without clear signal
            self.probe_salesforce_subdomains()
            sf_subs = self.results.get("subdomains", {}).get("salesforce_count", 0)
            if sf_subs > 0:
                self.results["detected"] = True
                self.enumerate_api_versions()
                self.check_unauthenticated_endpoints()

        return self.results
