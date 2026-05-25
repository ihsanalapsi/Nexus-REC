"""
Azure Cloud Reconnaissance — Detect Azure App Services, Front Door,
IP Restrictions, Blob Storage, and CDN profiles.
"""

import re
import socket
import requests
import concurrent.futures


# Azure App Service environment suffixes
APP_SERVICE_SUFFIXES = [
    ".azurewebsites.net",
    ".azurewebsites.org",
    ".scm.azurewebsites.net",
]

# Azure Front Door signatures
FRONTDOOR_HEADERS = [
    "x-azure-ref",
    "x-cdn",
    "x-frontdoor-id",
]

# Azure Blob Storage endpoints
BLOB_ENDPOINTS = [
    ".blob.core.windows.net",
    ".blob.storage.azure.net",
]

# Azure WAF / IP Restriction headers
IP_RESTRICTION_HEADERS = [
    "x-ms-forbidden-ip",
    "x-ms-ip-restriction",
]

# Common Azure storage account name variations
STORAGE_VARIATIONS = [
    "{domain}",
    "{domain_no_dot}",
    "{domain_with_hyphen}",
    "{first_part}",
    "{first_part}assets",
    "{first_part}media",
    "{first_part}static",
    "{first_part}uploads",
    "{first_part}public",
    "{first_part}backup",
    "{first_part}data",
    "{first_part}files",
    "{first_part}images",
    "{first_part}cdn",
    "{first_part}dev",
    "{first_part}staging",
    "{first_part}prod",
    "{first_part}storage",
    "{first_part}blob",
]


class AzureCloudRecon:
    """Detect Azure cloud infrastructure including App Services,
    Storage, Front Door, and access restrictions."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.base_domain = ".".join(self.domain.split(".")[-2:])
        self.results = {}
        self.scan_mode = "safe"
        self.stealth = False
        self.max_workers = 10
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
        })

    def detect_azure_app_service(self):
        """Detect if the target is hosted on Azure App Service and
        enumerate common Azure App Service subdomains."""
        findings = []

        # Check current target
        try:
            r = self._session.get(self.target_url, timeout=10)
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Check for App Service signature headers
            server = r.headers.get("Server", "")
            if "Microsoft-IIS" in server:
                findings.append({
                    "type": "app_service",
                    "source": "current_target",
                    "detected_by": "Server header: Microsoft-IIS",
                    "url": self.target_url,
                })

            # Check for Azure Blob via x-ms-* headers
            for h in headers:
                if h.startswith("x-ms"):
                    findings.append({
                        "type": "azure_service",
                        "source": "current_target",
                        "detected_by": f"Header: {h}={headers[h][:80]}",
                        "url": self.target_url,
                    })
                    break

            # Check for IP Restriction (forbidden)
            ip_restriction = r.headers.get("x-ms-forbidden-ip", "")
            if ip_restriction:
                findings.append({
                    "type": "ip_restriction",
                    "source": "current_target",
                    "detected_by": "x-ms-forbidden-ip header",
                    "blocked_ip": ip_restriction,
                    "url": self.target_url,
                    "severity": "info",
                    "note": f"Azure IP Restriction active — IP {ip_restriction} is blocked",
                })

            # Check for Front Door
            for fd_header in FRONTDOOR_HEADERS:
                if fd_header in headers:
                    findings.append({
                        "type": "front_door",
                        "source": "current_target",
                        "detected_by": f"Header: {fd_header}",
                        "url": self.target_url,
                    })
                    break

            # Check for Azure CDN
            if "x-cdn" in headers:
                findings.append({
                    "type": "azure_cdn",
                    "source": "current_target",
                    "detected_by": "x-cdn header",
                    "url": self.target_url,
                })

            # Check cookie ARRAffinity (Azure App Service affinity cookie)
            set_cookie = r.headers.get("Set-Cookie", "")
            if "ARRAffinity=" in set_cookie:
                findings.append({
                    "type": "app_service",
                    "source": "current_target",
                    "detected_by": "Cookie: ARRAffinity (Azure App Service affinity)",
                    "url": self.target_url,
                })

            # Check for request-context header (Azure specific)
            if "request-context" in headers:
                findings.append({
                    "type": "azure_service",
                    "source": "current_target",
                    "detected_by": "Header: request-context",
                    "url": self.target_url,
                })

        except requests.RequestException:
            pass

        # Check if domain itself is on azurewebsites.net
        if self.domain.endswith(".azurewebsites.net"):
            findings.append({
                "type": "app_service",
                "source": "domain_name",
                "detected_by": f"Domain {self.domain} is an Azure App Service",
                "url": self.target_url,
            })

        self.results["azure_app_service"] = findings
        return findings

    def enumerate_app_service_subdomains(self):
        """Enumerate common Azure App Service subdomains for the target domain."""
        if self.scan_mode == "safe":
            self.results["app_service_subdomains"] = {
                "skipped": True,
                "note": "Skipped in safe mode — would probe *.azurewebsites.net subdomains",
            }
            return self.results["app_service_subdomains"]

        findings = []
        first_part = self.domain.split(".")[0]

        candidates = [
            f"api-{first_part}",
            f"api-{self.base_domain.replace('.', '-')}",
            f"{first_part}-api",
            f"{first_part}-dev",
            f"{first_part}-staging",
            f"{first_part}-admin",
            f"{first_part}-backend",
            f"dev-{first_part}",
            f"staging-{first_part}",
            f"admin-{first_part}",
            f"{first_part}api",
            f"{first_part}dev",
            f"{first_part}admin",
            f"{first_part}test",
        ]

        def check_candidate(name):
            for suffix in APP_SERVICE_SUFFIXES:
                url = f"https://{name}{suffix}"
                try:
                    r = self._session.get(url, timeout=8, allow_redirects=True)
                    if r.status_code not in [404]:
                        return {
                            "subdomain": f"{name}{suffix}",
                            "url": url,
                            "status": r.status_code,
                            "server": r.headers.get("Server", ""),
                            "content_length": len(r.content),
                        }
                except (requests.RequestException, socket.gaierror):
                    pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            results = list(ex.map(check_candidate, candidates))

        for r in results:
            if r:
                findings.append(r)

        # Sort by status code
        findings.sort(key=lambda x: x.get("status", 0))

        self.results["app_service_subdomains"] = findings
        return findings

    def detect_azure_front_door(self):
        """Detect Azure Front Door via CDN challenge headers."""
        findings = []
        try:
            r = self._session.get(self.target_url, timeout=10)
            headers = r.headers

            # Front Door challenges
            x_azure_ref = headers.get("X-Azure-Ref", "")
            x_cdn = headers.get("X-CDN", "")
            x_frontdoor_id = headers.get("X-Frontdoor-ID", "")

            if x_azure_ref:
                findings.append({
                    "detected": True,
                    "header": "X-Azure-Ref",
                    "value": x_azure_ref[:40],
                })
            if x_cdn:
                findings.append({
                    "detected": True,
                    "header": "X-CDN",
                    "value": x_cdn[:40],
                })
            if x_frontdoor_id:
                findings.append({
                    "detected": True,
                    "header": "X-Frontdoor-ID",
                    "value": x_frontdoor_id[:40],
                })

            # Diagnostics: X-Azure-Ref encodes Front Door POP
            if x_azure_ref:
                pop_match = re.search(r'^[0-9A-F]{16}', x_azure_ref.split("20")[0])
                if pop_match:
                    findings.append({
                        "pop_location": x_azure_ref[:16],
                        "note": "Azure Front Door Point of Presence code",
                    })

        except requests.RequestException:
            pass

        self.results["azure_front_door"] = findings if findings else {"detected": False}
        return self.results["azure_front_door"]

    def detect_azure_blob_storage(self):
        """Detect Azure Blob Storage accounts related to the target."""
        findings = []
        first_part = self.domain.split(".")[0]
        domain_no_dot = self.domain.replace(".", "")
        domain_hyphen = self.domain.replace(".", "-")

        storage_names = []
        for tmpl in STORAGE_VARIATIONS:
            name = tmpl.format(
                domain=self.domain,
                domain_no_dot=domain_no_dot,
                domain_with_hyphen=domain_hyphen,
                first_part=first_part,
            )
            storage_names.append(name)

        def check_storage(name):
            url = f"https://{name}.blob.core.windows.net"
            try:
                r = self._session.get(url, timeout=8)
                if r.status_code not in [404]:
                    result = {
                        "storage_account": name,
                        "url": url,
                        "status": r.status_code,
                    }
                    # Check for x-ms-* headers that indicate Azure Storage
                    headers = r.headers
                    if "x-ms-request-id" in headers:
                        result["azure_storage"] = True
                    if "x-ms-version" in headers:
                        result["x-ms-version"] = headers.get("x-ms-version", "")
                    return result
            except requests.RequestException:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            results = list(ex.map(check_storage, storage_names))

        for r in results:
            if r:
                findings.append(r)

        self.results["azure_blob_storage"] = findings
        return findings

    def detect_ip_restriction(self):
        """Probe for Azure IP Restrictions by checking for forbidden headers."""
        findings = []
        paths_to_test = [
            "/",
            "/admin",
            "/dashboard",
            "/api",
            "/api/v1",
            "/.well-known",
        ]

        for path in paths_to_test:
            url = f"{self.target_url}{path}"
            try:
                r = self._session.get(url, timeout=10)
                forbidden_ip = r.headers.get("x-ms-forbidden-ip", "")
                if forbidden_ip:
                    findings.append({
                        "path": path,
                        "url": url,
                        "status": r.status_code,
                        "blocked_ip": forbidden_ip,
                        "mechanism": "Azure App Service IP Restriction",
                    })
                # Also check for generic 403 with Azure signature
                if r.status_code == 403:
                    body = r.text[:500].lower()
                    if "the web app you have attempted to reach has blocked" in body:
                        findings.append({
                            "path": path,
                            "url": url,
                            "status": 403,
                            "mechanism": "Azure App Service IP Restriction (detected via 403 body)",
                        })
            except requests.RequestException:
                pass

        self.results["ip_restriction"] = findings
        return findings

    def check_request_context(self):
        """Parse Azure request-context header for app insights."""
        try:
            r = self._session.get(self.target_url, timeout=10)
            rc = r.headers.get("request-context", "")
            if rc:
                # Parse appId pattern
                app_id_match = re.search(r'appId=cid-v1:([\w-]+)', rc)
                if app_id_match:
                    self.results["request_context"] = {
                        "detected": True,
                        "app_id": app_id_match.group(1)[:40],
                        "note": "Azure App Insights request-context header detected",
                    }
                    return self.results["request_context"]
        except requests.RequestException:
            pass
        self.results["request_context"] = {"detected": False}
        return self.results["request_context"]

    def run_all(self):
        """Run all Azure cloud checks respecting scan mode."""
        self.results = {
            "scan_mode": self.scan_mode,
            "stealth": self.stealth,
        }

        # Passive checks (safe in all modes)
        self.detect_azure_app_service()
        self.detect_azure_front_door()
        self.detect_azure_blob_storage()
        self.detect_ip_restriction()
        self.check_request_context()

        # Active checks (gated)
        if self.scan_mode != "safe":
            self.enumerate_app_service_subdomains()

        return self.results
