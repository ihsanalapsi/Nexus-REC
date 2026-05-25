<div align="center">
  <img src="https://cdn.ihsanalapsi.dev/banner.png" width="100%" alt="Nexus-REC Banner">
</div>

# 🛡️ Nexus-REC
### The Intelligent Reconnaissance & Vulnerability Assessment Framework

[![Version](https://img.shields.io/github/v/release/ihsanalapsi/Nexus-REC?style=for-the-badge)](https://github.com/ihsanalapsi/Nexus-REC/releases)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/nexus-rec?style=for-the-badge)](https://pypi.org/project/nexus-rec/)
[![CI](https://img.shields.io/github/actions/workflow/status/ihsanalapsi/Nexus-REC/ci.yml?style=for-the-badge)](https://github.com/ihsanalapsi/Nexus-REC/actions)

---

**Nexus-REC** is a modular reconnaissance and vulnerability assessment engine built for **Red Teams, Bug Bounty Hunters, and Security Researchers**. It integrates **539+ specialized techniques** — from passive OSINT to active exploitation — into a single, automated workflow driven by a context-aware Smart Scan engine.

[Quick Start](#-quick-start) · [Capabilities](#-capabilities) · [Smart Scan](#-smart-scan-logic) · [Installation](#-installation) · [Usage](#-usage) · [Architecture](#-architecture) · [Reports](#-reports) · [Arabic README](README.ar.md)

---

## Why Nexus-REC?

The gap between **shipping code** and **testing it** is where vulnerabilities slip through. Most reconnaissance tools are:

- ❌ **Single-purpose** — one tool for subdomains, another for JS analysis, another for cloud buckets
- ❌ **Static** — run the same checks on every target regardless of technology stack
- ❌ **Noisy** — no awareness of WAF, rate limits, or security challenges
- ❌ **Poor reporting** — raw terminal output with no structured evidence

Nexus-REC solves this with a **unified pipeline** that fingerprints the target first, then builds a smart plan based on what it finds — running only the relevant modules, respecting security boundaries, and producing structured JSON + Markdown + PDF reports with full evidence preservation.

### What Makes It Different

| Capability | Nexus-REC | Typical Tools |
|---|---|---|
| **Stack-aware scanning** | Detects framework (Next.js, Laravel, ASP.NET) and runs targeted checks | Blind scans |
| **Smart plan engine** | Adapts module selection based on real-time fingerprinting | Fixed checklist |
| **539+ techniques** | Recon, exploitation, cloud, mobile, API docs, email security, and more | 10–50 checks |
| **Structured reports** | JSON + Markdown + PDF with full evidence | Raw terminal output |
| **Safety gates** | WAF detection, security challenge handling, rate-limit awareness | No awareness |
| **Multi-language** | English + Arabic interfaces and documentation | English only |

---

## 📊 Engine Stats

| Scanners | Modules | Patterns | 
|:--------:|:-------:|:--------:|
| **539+** | **29** | **39+** |

---

## 🚀 Capabilities

Nexus-REC ships **29 modules** organized across reconnaissance, exploitation, infrastructure, and stack-specific analysis. Each module is independently runnable and contributes findings to a unified report.

### Reconnaissance

| Module | Category | Highlights |
|---|---|---|
| **Basic Recon** | 🔍 | WAF detection (13 engines), technology stack (30+ frameworks), security headers audit, CSP parsing, HTML metadata extraction |
| **Subdomain Enumeration** | 🌐 | Certificate transparency (crt.sh), DNS brute force (incl. bkapi, student, teacher patterns), JS-based extraction, backend IP discovery |
| **DNS, SSL & Ports** | 🔒 | Wildcard detection, SSL certificate parsing, 25-port scan, DNSSEC check |
| **DNS Detritus** | 🗑️ | Legacy DNS record mapping, Cloudflare stale record resolution, historical subdomain discovery |
| **Cloud Recon** | ☁️ | AWS S3/CloudFront, Azure Blob Storage, Cloudflare detection, cache poisoning assessment |
| **Azure Cloud Recon** | ☁️ | Azure App Service detection, Front Door identification, IP Restriction detection (`x-ms-forbidden-ip`), Blob Storage enumeration, App Service subdomain scanning |
| **JavaScript Analysis** | 📜 | API endpoint extraction, webpack chunk parsing, secret/token harvesting, AWS Amplify config extraction (AppSync, Cognito, S3) |
| **Well-Known Files** | 📄 | robots.txt, security.txt, llms.txt & ai.txt parsing for intelligence gathering |
| **Email Security** | 📧 | MX record enumeration, SPF/DMARC/DKIM analysis, email provider identification, security scoring |
| **Salesforce Detection** | ☁️ | Instance detection via headers/HTML, subdomain probing, API version enumeration, unauthenticated endpoint checks |
| **API Doc Discovery** | 📚 | ASP.NET Web API Help Page parsing, generic API documentation discovery, controller/action extraction, auth requirement analysis |

### Exploitation & Vulnerability Assessment

| Module | Category | Highlights |
|---|---|---|
| **Vulnerability Scanner** | 🔴 | SQLi, XSS, IDOR (PII-aware), SSRF, XXE, auth bypass, mass assignment, payment data leak |
| **Business Logic** | ⚖️ | Price manipulation, race conditions, coupon abuse, logic flow bypass |
| **Registration Security** | 🔐 | Registration endpoint discovery, OTP requirement check, role manipulation detection (admin escalation), safe vs. elevated role comparison |
| **Auth Security Scanner** | 🔑 | Unauthenticated PII leak detection (phone, email, name exposure), admin endpoint probing, API auth enforcement comparison |
| **Cookie & Session** | 🍪 | JWT decoding, HS256 offline secret cracking, security flag audit, session ID analysis |
| **Endpoint Discovery** | 🔗 | Path enumeration, parameter discovery, hidden endpoint detection |

### Infrastructure & Platform

| Module | Category | Highlights |
|---|---|---|
| **Admin Deep Scan** | 🔐 | Admin subdomain discovery, interface deep scanning, path enumeration (active/aggressive modes only) |
| **Backend API Scan** | 🔗 | Backend host discovery from JS, follow-up API scanning, cross-origin API analysis |
| **GraphQL Recon** | 🕸️ | Introspection check, error-based schema harvesting, Apollo CSRF preflight check, batching analysis, AppSync multi-auth detection |
| **CORS Deep Scan** | 🌐 | Origin reflection, credential+wildcard detection, preflight analysis, method enumeration |
| **OpenAPI / Swagger** | 📖 | Spec discovery (YAML/JSON), endpoint extraction, auth requirement mapping |
| **Server Leak Detection** | 📡 | Leaky header analysis, server timing metadata, environment fingerprinting, version disclosure, internal region detection |

### Stack-Specific

| Module | Stack | Highlights |
|---|---|---|
| **Next.js Deep Inspection** | 💎 Next.js | Middleware bypass, SSG/SSR leak, build manifest route extraction, JS chunk harvesting, Turbopack detection, Sentry, proxy scan |
| **Laravel Deep Inspection** | 💎 Laravel | Debug mode detection, Boost package analysis, WAF/OpenResty identification, Coolify detection, server audit |
| **Atlassian Stack** | 🔷 Atlassian | Jira info disclosure, anonymous endpoint check, dashboard content leak, Confluence/Bitbucket detection, Azure App Proxy detection, SAML SSO |
| **Supabase RLS** | 🛢️ Supabase | Row-Level Security policy testing, anon key exposure check |
| **Supabase RPC** | 🛢️ Supabase | Remote Procedure Call enumeration, exposed function discovery |
| **Supabase Storage** | 🛢️ Supabase | Storage bucket audit, public bucket detection, misconfiguration analysis |

### Mobile

| Module | Category | Highlights |
|---|---|---|
| **APK / Mobile Analysis** | 📱 | APK/AAB download and analysis, DEX decompiling, API endpoint extraction, hardcoded secret discovery |

---

## 🧠 Smart Scan Logic

The Smart Scan is the core differentiator — it adapts the module pipeline to each target automatically.

### How It Works

```
         ┌──────────────────────────┐
         │   Phase 0: Fingerprint   │
         │   (Basic Recon - ALWAYS) │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  Analyze: Stack, WAF,    │
         │  Headers, CSP, HTML, JS  │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  Build Smart Plan        │
         │  (29 modules → subset)   │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  Execute Selected Steps  │
         │  + Expand if new signals │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  Generate Reports        │
         │  (JSON + Markdown + PDF) │
         └──────────────────────────┘
```

### Decision Rules

The smart planner evaluates these signals after fingerprinting:

| Signal | Effect |
|---|---|
| **Next.js detected** | Enables Next.js deep inspection (build routes, chunks, proxy) |
| **Laravel detected** | Enables Laravel debug/boost/Coolify checks |
| **Supabase detected** | Enables RLS testing, RPC enumeration, storage audit |
| **ASP.NET / IIS detected** | Enables Azure Cloud Recon, API Doc Discovery |
| **GraphQL / Apollo detected** | Enables GraphQL introspection and CSRF checks |
| **Registration/Auth endpoints found** | Enables Registration Security Analysis |
| **API endpoints detected** | Enables Auth Security & PII leak scanner |
| **Payment gateway in CSP** | Enables Payment Gateway Recon |
| **Salesforce indicators** | Enables Salesforce Instance Detection |
| **JavaScript framework found** | Enables JS analysis, secret scanning, APK checks |
| **CORS headers present** | Enables CORS deep configuration scan |
| **WAF / Security Challenge** | Skips HTTP-heavy modules, focuses on passive DNS/infra |
| **Active/aggressive mode** | Enables admin_scan, business logic, full vulnerability scanning |

Every decision is recorded in the report metadata (`smart_plan_reasons`, `smart_skip_reasons`) so you know exactly why each module was included or excluded.

---

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install nexus-rec
```

### From Source

```bash
git clone https://github.com/ihsanalapsi/Nexus-REC.git
cd Nexus-REC
pip install -r requirements.txt
```

Verify the environment:

```bash
python3 nexus_rec.py --check-deps
```

---

## 🚀 Quick Start

Start an interactive scan:

```bash
python3 nexus_rec.py
```

This walks you through:
1. Target domain or URL
2. Scan mode: `safe`, `active`, or `aggressive`
3. Stealth mode
4. Redacted report export
5. Authorization confirmation (for active/aggressive modes)
6. Scan profile selection

### Non-Interactive (CI/CD)

```bash
# Quick fingerprint
nexus-rec example.com --modules basic --auto

# Full smart scan
nexus-rec example.com --auto

# Authorized vulnerability assessment
nexus-rec example.com --scan-mode active --i-have-authorization --auto

# Specific modules only
nexus-rec example.com --modules basic,js,vuln,registration --auto
```

---

## ⚙️ CLI Reference

| Option | Purpose |
|---|---|
| `target` | Domain or URL (e.g., `example.com` or `https://example.com`) |
| `--auto` | Non-interactive mode — skip all prompts |
| `--modules` | Comma-separated module list (bypasses profile selector) |
| `--scan-mode safe` | Default — no state-changing payloads |
| `--scan-mode active` | Authorized active vulnerability checks |
| `--scan-mode aggressive` | Higher-noise authorized checks |
| `--i-have-authorization` | Required for active/aggressive modes |
| `--stealth` | Lower concurrency, add request delays |
| `--redact-report` | Also write a shareable redacted JSON report |
| `--debug` | Full Python tracebacks for troubleshooting |
| `--check-deps` | Verify required/optional dependencies |

### Available Modules

```
basic, subdomain, cloud, js, graphql, secrets, vuln, business, cookies, dns,
endpoints, payment, supabase_rls, supabase_rpc, supabase_storage, wellknown,
apk, dns_detritus, admin_scan, backend_scan, nextjs, laravel, atlassian,
cors, openapi, server_leaks, api_docs, email_recon, salesforce,
registration, azure_cloud, auth_security
```

---

## 📁 Project Architecture

```
nexus_rec.py               # Orchestration engine (CLI, pipeline, reporting)
├── modules/
│   ├── core/              # Config, pipeline, module loader, summary, reporter, CLI
│   ├── recon/
│   │   ├── fingerprint/   # Basic recon, WAF, technology detection
│   │   ├── web/           # JS, cookies, secrets, GraphQL, CORS, payment, server leaks
│   │   ├── infra/         # DNS, subdomains, cloud, admin scan, email, Azure
│   │   ├── platforms/     # Supabase (RLS, RPC, storage)
│   │   └── mobile/        # APK analysis
│   ├── exploit/           # Vulnerability scanner, business logic, registration, auth
│   └── stack/             # Next.js, Laravel, Atlassian
├── tests/                 # Smoke tests (registry, smart plan, CLI, dependencies)
├── results/               # Per-scan output (JSON, MD, PDF)
└── requirements.txt
```

---

## 📊 Reports

Each scan produces a timestamped folder:

```
results/YYYYMMDD_HHMMSS-domain/
├── raw_report.json         # Complete evidence (redactable)
├── redacted_report.json    # Only with --redact-report
├── security_report.md      # Human-readable Markdown
└── security_report.pdf     # Portable PDF version
```

Reports include:
- **Executive summary** with target metadata, scan coverage, and module decisions
- **Technologies** detected with evidence sources
- **Security headers** audit
- **Smart plan decisions** (why each module ran or was skipped)
- **Findings overview** with counts per module
- **Detailed sections** for each module that produced results
- **Raw JSON evidence** for automation and deep inspection



## 🔎 Safety Model

| Mode | Behavior |
|---|---|
| `safe` (default) | Read-only reconnaissance; no state-changing payloads; skips admin scans and business logic |
| `active` | Authorized vulnerability testing with payloads; requires `--i-have-authorization` |
| `aggressive` | Authorized high-noise checks (race conditions, replay attacks); requires `--i-have-authorization` |

- All raw findings are preserved locally
- `--redact-report` strips sensitive values (tokens, keys, credentials) for sharing
- WAF/CDN detection can gate HTTP-heavy modules automatically

---

## 🧯 Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `Vercel Security Challenge` | Target returns edge security page | Retry later, use authorized IP, or run passive modules |
| `Invalid module(s)` | Unknown module name | Check the valid module list above |
| `Dependency check` warning | Missing optional package | Run `pip install -r requirements.txt` |
| Unexpected error | Runtime exception | Re-run with `--debug` for full traceback |

---

## ⚠️ Ethical Disclaimer

This tool is intended for **authorized security testing and educational research only**. You must have explicit, written permission from the system owner before using Nexus-REC against any target. Unauthorized use is illegal.

---

## 📖 Documentation

- [Arabic README (README.ar.md)](README.ar.md) — Full documentation in Arabic
- [GitHub Issues](https://github.com/ihsanalapsi/Nexus-REC/issues) — Bug reports and feature requests

---

<div align="center">

**Developed by [Ihsan Alapsi](https://ihsanalapsi.dev)** · Software Engineer & Cyber Security Researcher

[GitHub](https://github.com/ihsanalapsi) · [LinkedIn](https://www.linkedin.com/in/ihsan-alapsi/)

</div>
