"""
Email Security Recon — Analyze email infrastructure security posture.

Extracted technique from Authorized reconnaissance findings:
- SPF: `v=spf1 include:_spf.google.com ~all` (soft fail — spoofable)
- MX: Google Workspace (`smtp.google.com`) + private mail server (`mail.target.com`)
- IMAP/SMTP ports open: 25, 110, 143, 465, 587, 993, 995
- SMTP credentials extracted from database: 12 accounts, 1 confirmed working
- BCC interceptor detected on password reset emails

This module performs:
- MX record enumeration
- SPF record lookup and analysis
- DMARC policy detection
- DKIM record discovery
- Email provider identification
"""

import concurrent.futures
import re
import socket
import dns.resolver
import dns.exception


# Known email provider signatures
EMAIL_PROVIDERS = {
    "Google Workspace": {
        "mx": ["aspmx.l.google.com", "googlemail.com"],
        "spf": ["_spf.google.com"],
        "dkim_selectors": ["google"],
    },
    "Microsoft 365": {
        "mx": ["protection.outlook.com", "mail.protection.outlook.com"],
        "spf": ["spf.protection.outlook.com"],
        "dkim_selectors": ["selector1", "selector2"],
    },
    "Zoho Mail": {
        "mx": ["mx.zoho.com", "mx.zoho.in", "mx.zohocorp.com"],
        "spf": ["spf.zoho.com"],
    },
    "FastMail": {
        "mx": ["messagingengine.com"],
        "spf": ["spf.messagingengine.com"],
    },
    "Mailgun": {
        "mx": ["mailgun.org"],
        "spf": ["mailgun.org"],
    },
    "SendGrid": {
        "mx": ["sendgrid.net"],
        "spf": ["sendgrid.net"],
    },
    "MailEnable": {
        # Self-hosted, no standard signatures
        "ports": [25, 110, 143, 465, 587, 993, 995],
    },
}


# Common DKIM selectors to try
DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "mail",
    "dkim", "mx", "smtp", "email", "protonmail", "zoho",
]


class EmailRecon:
    """Analyze email security for a domain."""

    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False

    def _resolve_dns(self, record_type, name=None):
        """Generic DNS resolver."""
        target = name or self.domain
        try:
            answers = dns.resolver.resolve(target, record_type)
            return [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []

    def check_mx_records(self):
        """Enumerate and analyze MX records."""
        findings = {"records": [], "providers": [], "mx_count": 0}
        parsed = []
        try:
            answers = dns.resolver.resolve(self.domain, "MX")
            for rdata in answers:
                priority = rdata.preference
                server = str(rdata.exchange).rstrip(".")
                parsed.append({"priority": priority, "server": server})
            parsed.sort(key=lambda x: x["priority"])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass

        findings["records"] = parsed
        findings["mx_count"] = len(parsed)

        # Identify providers
        providers = set()
        for mx in parsed:
            server = mx["server"]
            for provider, sigs in EMAIL_PROVIDERS.items():
                if "mx" in sigs:
                    if any(sp in server for sp in sigs["mx"]):
                        providers.add(provider)
                        break
            else:
                if "MailEnable" not in providers:
                    # Check if self-hosted (not a major cloud provider)
                    is_cloud = any(
                        cloud in server
                        for cloud in [
                            "google", "outlook", "microsoft", "zoho",
                            "fastmail", "mailgun", "sendgrid", "protonmail",
                        ]
                    )
                    if not is_cloud:
                        providers.add("Self-Hosted / Custom")

        findings["providers"] = sorted(providers)
        self.results["mx"] = findings
        return findings

    def check_spf_record(self):
        """Lookup and analyze SPF record."""
        findings = {
            "record": None,
            "raw": None,
            "mechanisms": [],
            "all_qualifier": None,
        }
        txt_records = self._resolve_dns("TXT")
        spf_record = None

        for txt in txt_records:
            if txt.startswith("v=spf1"):
                spf_record = txt
                break

        if not spf_record:
            findings["record"] = "MISSING"
            findings["severity"] = "HIGH"
            findings["note"] = "No SPF record found — domain is vulnerable to email spoofing"
            self.results["spf"] = findings
            return findings

        findings["raw"] = spf_record
        findings["record"] = spf_record[:200]

        # Parse mechanisms
        mechanisms = spf1_parser(spf_record)
        findings["mechanisms"] = mechanisms

        # Determine all qualifier
        all_match = re.search(r'\s+([-~+?]?all)\s*$', spf_record)
        if all_match:
            qualifier = all_match.group(1)
            findings["all_qualifier"] = qualifier
            if qualifier == "-all":
                findings["severity"] = "LOW"
                findings["note"] = "SPF hard fail (-all) — strong protection against spoofing"
            elif qualifier == "~all":
                findings["severity"] = "MEDIUM"
                findings["note"] = "SPF soft fail (~all) — spoofing possible but taggable"
            elif qualifier == "?all":
                findings["severity"] = "HIGH"
                findings["note"] = "SPF neutral (?all) — no protection against spoofing"
            else:
                findings["severity"] = "MEDIUM"
                findings["note"] = f"SPF all qualifier: '{qualifier}' — ambiguous protection"

        # Check for suspicious includes
        for mech in mechanisms:
            if mech["type"] == "include":
                include_domain = mech.get("value", "")
                # Check if included domain has SPF
                if include_domain:
                    try:
                        inc_txt = dns.resolver.resolve(include_domain, "TXT")
                        has_spf = any(r.to_text().startswith('"v=spf1') for r in inc_txt)
                        mech["resolves"] = has_spf
                    except Exception:
                        mech["resolves"] = False

        self.results["spf"] = findings
        return findings

    def check_dmarc_record(self):
        """Lookup and analyze DMARC record."""
        findings = {
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "rua": None,
            "ruf": None,
            "severity": None,
        }
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            dmarc_record = None
            for ans in answers:
                txt = ans.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break

            if not dmarc_record:
                findings["record"] = "MISSING"
                findings["severity"] = "HIGH"
                findings["note"] = "No DMARC record found — no reporting or enforcement on email spoofing"
                self.results["dmarc"] = findings
                return findings

            findings["record"] = dmarc_record[:200]

            # Parse policy
            p_match = re.search(r'\bp=(\w+)', dmarc_record)
            if p_match:
                policy = p_match.group(1)
                findings["policy"] = policy
                if policy == "reject":
                    findings["severity"] = "LOW"
                    findings["note"] = f"DMARC policy: {policy} — strong protection"
                elif policy == "quarantine":
                    findings["severity"] = "MEDIUM"
                    findings["note"] = f"DMARC policy: {policy} — moderate protection"
                else:
                    findings["severity"] = "HIGH"
                    findings["note"] = f"DMARC policy: {policy} (none) — no enforcement, monitoring only"

            sp_match = re.search(r'\bsp=(\w+)', dmarc_record)
            if sp_match:
                findings["subdomain_policy"] = sp_match.group(1)

            pct_match = re.search(r'\bpct=(\d+)', dmarc_record)
            if pct_match:
                findings["pct"] = int(pct_match.group(1))

            rua_match = re.search(r'\brua=([^\s;]+)', dmarc_record)
            if rua_match:
                findings["rua"] = rua_match.group(1)

            ruf_match = re.search(r'\bruf=([^\s;]+)', dmarc_record)
            if ruf_match:
                findings["ruf"] = ruf_match.group(1)

        except dns.resolver.NXDOMAIN:
            findings["record"] = "MISSING"
            findings["severity"] = "HIGH"
            findings["note"] = "DMARC subdomain does not exist — no DMARC protection"
        except Exception as e:
            findings["error"] = str(e)

        self.results["dmarc"] = findings
        return findings

    def check_dkim_records(self):
        """Attempt to discover DKIM records using common selectors."""
        findings = {"selectors_tested": [], "found": []}
        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            try:
                answers = dns.resolver.resolve(dkim_domain, "TXT")
                for ans in answers:
                    txt = ans.to_text()
                    if "v=DKIM1" in txt or "k=rsa" in txt:
                        findings["found"].append({
                            "selector": selector,
                            "domain": dkim_domain,
                            "record_preview": txt[:150],
                        })
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception:
                pass
            finally:
                findings["selectors_tested"].append(selector)

        findings["total_found"] = len(findings["found"])
        self.results["dkim"] = findings
        return findings

    def check_reverse_dns_ptr(self):
        """Check PTR record for mail server identification."""
        findings = {"ptr_records": []}
        try:
            ip = socket.gethostbyname(self.domain)
            rev_domain = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            try:
                answers = dns.resolver.resolve(rev_domain, "PTR")
                for ans in answers:
                    findings["ptr_records"].append(str(ans).rstrip("."))
            except Exception:
                pass
        except Exception:
            pass
        findings["ptr_count"] = len(findings["ptr_records"])
        self.results["ptr"] = findings
        return findings

    def check_email_provider_security(self):
        """Combine findings to assess overall email security posture."""
        findings = {"score": 0, "issues": [], "strengths": []}

        spf = self.results.get("spf", {})
        dmarc = self.results.get("dmarc", {})
        mx = self.results.get("mx", {})
        dkim = self.results.get("dkim", {})

        score = 0  # out of 10

        # MX analysis
        if mx.get("mx_count", 0) > 0:
            score += 1
            if mx.get("mx_count", 0) > 1:
                score += 1  # Redundancy

        # SPF analysis
        spf_severity = spf.get("severity", "HIGH")
        if spf_severity == "LOW":
            score += 2
            findings["strengths"].append("SPF hard fail (-all)")
        elif spf_severity == "MEDIUM":
            score += 1
            findings["issues"].append("SPF soft fail (~all) — spoofing possible")
        else:
            findings["issues"].append("SPF missing or weak — domain can be spoofed")

        # DMARC analysis
        dmarc_policy = dmarc.get("policy", "none")
        if dmarc_policy == "reject":
            score += 2
            findings["strengths"].append(f"DMARC reject policy")
        elif dmarc_policy == "quarantine":
            score += 1
            findings["strengths"].append(f"DMARC quarantine policy")
        elif dmarc["record"] == "MISSING":
            findings["issues"].append("DMARC missing — no email authentication enforcement")
        else:
            findings["issues"].append(f"DMARC policy: p={dmarc_policy} (no enforcement)")

        if dmarc.get("rua"):
            score += 1
            findings["strengths"].append("DMARC reporting (rua) configured")

        # DKIM analysis
        if dkim.get("total_found", 0) > 0:
            score += 2
            findings["strengths"].append(f"DKIM configured ({dkim['total_found']} selector(s))")
        else:
            findings["issues"].append("DKIM not detected — no email signing")

        findings["score"] = score
        findings["max_score"] = 10
        if score >= 8:
            findings["rating"] = "Good"
        elif score >= 5:
            findings["rating"] = "Moderate"
        else:
            findings["rating"] = "Poor"

        self.results["security_summary"] = findings
        return findings

    def run_all(self):
        """Run all email recon checks."""
        self.check_mx_records()
        self.check_spf_record()
        self.check_dmarc_record()
        self.check_dkim_records()
        self.check_reverse_dns_ptr()
        self.check_email_provider_security()
        return self.results


def spf1_parser(spf_string):
    """Parse SPF record into mechanism list."""
    mechanisms = []
    # Remove quotes if present
    spf_string = spf_string.strip().strip('"')
    parts = spf_string.split()
    for part in parts:
        if part == "v=spf1":
            continue
        mechanism = {"raw": part, "type": "unknown", "value": None}

        # Parse qualifier
        if part[0] in ("+", "-", "~", "?"):
            qualifier = part[0]
            rest = part[1:]
        else:
            qualifier = "+"
            rest = part

        mechanism["qualifier"] = qualifier

        if rest.startswith("include:"):
            mechanism["type"] = "include"
            mechanism["value"] = rest[8:]
        elif rest.startswith("ip4:"):
            mechanism["type"] = "ip4"
            mechanism["value"] = rest[4:]
        elif rest.startswith("ip6:"):
            mechanism["type"] = "ip6"
            mechanism["value"] = rest[4:]
        elif rest.startswith("a"):
            mechanism["type"] = "a"
            if ":" in rest:
                mechanism["value"] = rest[2:]
        elif rest.startswith("mx"):
            mechanism["type"] = "mx"
            if ":" in rest:
                mechanism["value"] = rest[3:]
        elif rest == "all":
            mechanism["type"] = "all"
            mechanism["value"] = "all"
        elif rest.startswith("redirect="):
            mechanism["type"] = "redirect"
            mechanism["value"] = rest[9:]
        elif rest.startswith("exists:"):
            mechanism["type"] = "exists"
            mechanism["value"] = rest[7:]
        else:
            mechanism["type"] = "unknown"
            mechanism["value"] = rest

        mechanisms.append(mechanism)
    return mechanisms
