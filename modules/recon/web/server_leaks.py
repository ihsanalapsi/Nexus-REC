"""
Server Leak Detection — Extracts internal infrastructure details from response
headers, server timing, and version disclosure.

Extracted technique from Authorized reconnaissance findings:
- Server-Timing header revealed:
    dc:aws-fra (data center in Frankfurt)
    cg:global-production (control group)
    cg:regular-staging (staging environment)
- X-Debug-CSP-Nonce header presence
- Version headers (X-NF-SRV-Version, etc.)
- Timing-Allow-Origin header analysis
"""

import re

import requests


# Headers that commonly disclose internal information
LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-API-Version",
    "X-Backend-Server",
    "X-Upstream",
    "X-Cache",
    "X-Served-By",
    "X-Request-ID",
    "X-Amzn-RequestId",
    "X-Amz-Cf-Id",
    "X-NF-Request-ID",
    "X-NF-SRV-Version",
    "X-Debug-CSP-Nonce",
    "X-HS-Prerendered-Error",
    "X-HS-Reason",
    "X-HS-CFWorker-Meta",
    "X-HS-Portal-ID",
    "X-Robots-Tag",
    "Via",
    "CF-Ray",
    "CF-Cache-Status",
    "Timing-Allow-Origin",
    "Server-Timing",
    "Version",
    "Build-Version",
    "Revision",
    "X-Rev",
    "X-B3-TraceId",
    "X-Datadog-Trace-Id",
    "X-Datadog-Sampling-Priority",
    "X-Datadog-Span-Id",
]

# Server timing parameter patterns that indicate internal info
INTERNAL_SERVER_TIMING_PATTERNS = [
    ("dc", "Data Center"),
    ("cg", "Control Group / Environment"),
    ("zone", "Availability Zone"),
    ("region", "Region"),
    ("env", "Environment"),
    ("stage", "Deployment Stage"),
    ("cluster", "Cluster"),
    ("namespace", "Namespace"),
    ("pod", "Pod Name"),
    ("instance", "Instance ID"),
    ("rack", "Rack Location"),
    ("host", "Host Name"),
    ("az", "Availability Zone"),
]

# Known staging/development environment indicators in headers/server timing
ENVIRONMENT_INDICATORS = [
    "staging", "stage", "dev", "development", "test", "qa",
    "uat", "preprod", "pre-prod", "sandbox", "canary",
    "beta", "alpha", "experimental", "internal",
]


class ServerLeakDetector:
    """Detect server-side information leakage from headers and metadata."""

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
        """Main entry point: analyze server-side leaks."""
        findings = {
            "leaky_headers": {},
            "server_timing_analysis": {},
            "environment_detected": None,
            "environment_confidence": None,
            "internal_regions": [],
            "version_disclosures": [],
            "total_leaks": 0,
        }

        # Fetch the target
        response = self._fetch_target()
        if not response:
            self.results = findings
            return self.results

        headers = response.headers

        # 1. Extract leaky headers
        leaky = self._extract_leaky_headers(headers)
        findings["leaky_headers"] = leaky
        findings["total_leaks"] += len(leaky)

        # 2. Analyze server-timing header
        server_timing = headers.get("Server-Timing", "")
        if server_timing:
            analysis = self._analyze_server_timing(server_timing)
            findings["server_timing_analysis"] = analysis
            if analysis.get("internal_params"):
                findings["total_leaks"] += len(analysis["internal_params"])
            if analysis.get("environment"):
                findings["environment_detected"] = analysis["environment"]
                findings["environment_confidence"] = analysis.get("confidence", "low")
            if analysis.get("regions"):
                findings["internal_regions"].extend(analysis["regions"])

        # 3. Detect environment from all header values
        env_from_headers = self._detect_environment_from_headers(headers, leaky)
        if env_from_headers:
            if not findings["environment_detected"]:
                findings["environment_detected"] = env_from_headers
                findings["environment_confidence"] = "medium"
            elif findings["environment_detected"] != env_from_headers:
                # Conflicting signals - note it
                findings.setdefault("conflicting_signals", []).append(env_from_headers)

        # 4. Collect version disclosures
        versions = self._collect_version_disclosures(headers, leaky)
        findings["version_disclosures"] = versions
        findings["total_leaks"] += len(versions)

        self.results = findings
        return self.results

    def _fetch_target(self):
        """Fetch the target URL and return the response."""
        try:
            r = self._session.get(
                self.target_url,
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
            return r
        except Exception:
            return None

    def _extract_leaky_headers(self, headers):
        """Extract specific headers that may leak internal info."""
        leaky = {}
        for header in LEAKY_HEADERS:
            value = headers.get(header)
            if value:
                clean_header = header.lower().replace("-", "_")
                leaky[clean_header] = value
        return leaky

    def _analyze_server_timing(self, server_timing):
        """Parse and analyze Server-Timing header for internal info."""
        analysis = {
            "raw": server_timing,
            "params": {},
            "internal_params": [],
            "environment": None,
            "confidence": None,
            "regions": [],
        }

        parts = [p.strip() for p in server_timing.split(",")]
        for part in parts:
            # Parse: key;desc="value";dur=number
            match = re.match(r"(\w[\w.-]*)\s*;\s*(?:desc=\"?([^\";]*)\"?)?\s*(?:;?\s*dur=([\d.]+))?", part)
            if match:
                key = match.group(1).strip()
                desc = (match.group(2) or "").strip()
                dur = match.group(3)

                entry = {"key": key, "value": desc or dur or ""}
                analysis["params"][key] = entry

                # Check if this is an internal parameter
                for pattern, label in INTERNAL_SERVER_TIMING_PATTERNS:
                    if key.lower() == pattern.lower() or pattern.lower() in key.lower():
                        entry["internal_label"] = label
                        analysis["internal_params"].append(entry)
                        break

                # Detect environment from desc
                if desc:
                    desc_lower = desc.lower()
                    for indicator in ENVIRONMENT_INDICATORS:
                        if indicator in desc_lower:
                            analysis["environment"] = desc
                            analysis["confidence"] = "high" if "staging" in desc_lower or "prod" in desc_lower else "medium"
                            break

                # Extract region/DC info
                region_keywords = ["aws-", "gcp-", "azure-", "us-", "eu-", "ap-", "sa-"]
                if desc and any(kw in desc.lower() for kw in region_keywords):
                    analysis["regions"].append(desc)

        return analysis

    def _detect_environment_from_headers(self, headers, leaky_headers):
        """Detect staging/production environment from header values."""
        all_values = []

        # Check specific environment headers
        if "x_nf_srv_version" in leaky_headers:
            all_values.append(leaky_headers["x_nf_srv_version"])

        # Check all header values for environment indicators
        for key, value in leaky_headers.items():
            value_lower = value.lower()
            for indicator in ENVIRONMENT_INDICATORS:
                if indicator in value_lower:
                    return indicator.capitalize()

        return None

    def _collect_version_disclosures(self, headers, leaky_headers):
        """Collect version information from various headers."""
        versions = []

        # Known version headers
        version_headers = {
            "server": "Server",
            "x_powered_by": "X-Powered-By",
            "x_aspnet_version": "ASP.NET",
            "x_aspnetmvc_version": "ASP.NET MVC",
            "x_nf_srv_version": "Netlify Server",
            "version": "Version",
            "x_version": "X-Version",
            "x_api_version": "API Version",
        }

        for key, label in version_headers.items():
            value = leaky_headers.get(key)
            if value:
                # Extract version-like patterns
                ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[.-][a-zA-Z0-9]+)?)", value)
                if ver_match:
                    versions.append({
                        "header": label,
                        "version": ver_match.group(1),
                        "raw_value": value,
                    })
                else:
                    versions.append({
                        "header": label,
                        "version": value,
                        "raw_value": value,
                    })

        return versions
