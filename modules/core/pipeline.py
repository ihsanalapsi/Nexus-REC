from dataclasses import dataclass


@dataclass(frozen=True)
class StepDefinition:
    key: str
    title: str
    result_key: str | None = None
    registry_key: str | None = None
    stack: str | None = None
    baseline: bool = False
    http_heavy: bool = False
    active_only: bool = False
    smart_optional: bool = False
    reason: str = ""
    skip_reason: str = ""

    @property
    def output_key(self):
        return self.result_key or self.key

    @property
    def module_key(self):
        return self.registry_key or self.key


STEP_DEFINITIONS = [
    StepDefinition(
        "basic",
        "Target Fingerprinting & Headers",
        baseline=True,
        reason="Fingerprinting always runs first and feeds every later decision.",
    ),
    StepDefinition(
        "subdomain",
        "Subdomain Enumeration",
        baseline=True,
        reason="Baseline external surface mapping after fingerprinting.",
    ),
    StepDefinition(
        "cloud",
        "Cloud & Bucket Detection",
        baseline=True,
        reason="Baseline CDN/cloud and bucket exposure checks.",
    ),
    StepDefinition(
        "js",
        "JavaScript & API Extraction",
        http_heavy=True,
        reason="JavaScript framework/assets detected in fingerprinting or HTML.",
        skip_reason="No JavaScript framework or bundle indicators were detected.",
    ),
    StepDefinition(
        "graphql",
        "GraphQL Introspection",
        http_heavy=True,
        smart_optional=True,
        reason="GraphQL/Apollo technology or endpoint was detected.",
        skip_reason="No GraphQL/Apollo signal was detected before JavaScript extraction.",
    ),
    StepDefinition(
        "secrets",
        "Secrets & Exposed Files",
        http_heavy=True,
        reason="Client assets may expose public config, endpoints, or accidental secrets.",
        skip_reason="Secret scanning depends on HTML/JS assets; no useful asset signal was found.",
    ),
    StepDefinition(
        "nextjs",
        "Next.js Deep Inspection",
        registry_key="Next.js",
        stack="Next.js",
        http_heavy=True,
        reason="Next.js detected; framework-specific routes/assets checks are relevant.",
        skip_reason="Next.js was not detected.",
    ),
    StepDefinition(
        "laravel",
        "Laravel Deep Inspection",
        registry_key="Laravel",
        stack="Laravel",
        http_heavy=True,
        reason="Laravel detected; framework-specific debug/route checks are relevant.",
        skip_reason="Laravel was not detected.",
    ),
    StepDefinition(
        "atlassian",
        "Atlassian Stack Recon",
        registry_key="Atlassian",
        stack="Atlassian",
        http_heavy=True,
        reason="Atlassian product (Jira/Confluence/Bitbucket) detected; unauthenticated access checks are relevant.",
        skip_reason="No Atlassian product (Jira/Confluence/Bitbucket) was detected.",
    ),
    StepDefinition(
        "vuln",
        "Vulnerability Scanner",
        result_key="vulnerabilities",
        http_heavy=True,
        reason="Safe vulnerability checks are allowed in safe mode; active payloads remain gated.",
    ),
    StepDefinition(
        "business",
        "Business Logic Checks",
        result_key="business_logic",
        http_heavy=True,
        active_only=True,
        skip_reason="Business-logic probes require active/aggressive authorized mode.",
    ),
    StepDefinition(
        "cookies",
        "Cookie & Session Analysis",
        http_heavy=True,
        reason="Session and CSRF posture is relevant for web targets.",
    ),
    StepDefinition(
        "dns",
        "DNS, SSL & Port Analysis",
        baseline=True,
        reason="Baseline DNS, SSL, and port posture checks.",
    ),
    StepDefinition(
        "endpoints",
        "Endpoint Discovery",
        http_heavy=True,
        reason="Endpoint discovery is relevant after fingerprinting and asset extraction.",
    ),
    StepDefinition(
        "payment",
        "Payment Gateway & Billing Surface",
        result_key="payment_gateway",
        http_heavy=True,
        smart_optional=True,
        reason="Payment gateway domains/scripts/keys were detected in CSP or HTML.",
        skip_reason="No payment gateway indicators were detected in CSP or HTML.",
    ),
    StepDefinition(
        "supabase_rls",
        "Supabase RLS Policy Testing",
        http_heavy=True,
        smart_optional=True,
        reason="Supabase detected; anon/RLS exposure checks are relevant.",
        skip_reason="Supabase was not detected.",
    ),
    StepDefinition(
        "supabase_rpc",
        "Supabase RPC Enumeration",
        http_heavy=True,
        smart_optional=True,
        reason="Supabase detected; RPC exposure checks are relevant.",
        skip_reason="Supabase was not detected.",
    ),
    StepDefinition(
        "supabase_storage",
        "Supabase Storage Audit",
        http_heavy=True,
        smart_optional=True,
        reason="Supabase detected; storage bucket exposure checks are relevant.",
        skip_reason="Supabase was not detected.",
    ),
    StepDefinition(
        "wellknown",
        "Well-Known / llms.txt Discovery",
        http_heavy=True,
        reason="Well-known files, security.txt, and llms.txt are low-impact intelligence sources.",
    ),
    StepDefinition(
        "apk",
        "APK Analysis",
        http_heavy=True,
        smart_optional=True,
        reason="Mobile app references discovered in JavaScript/HTML metadata.",
        skip_reason="Mobile app references are checked after JavaScript/HTML discovery.",
    ),
    StepDefinition(
        "dns_detritus",
        "DNS Detritus Detection",
        baseline=True,
        reason="DNS-based stale record and legacy host checks are useful without HTTP access.",
    ),
    StepDefinition(
        "admin_scan",
        "Admin Subdomain Deep Scan",
        http_heavy=True,
        active_only=True,
        smart_optional=True,
        reason="Authorized active mode allows deeper admin surface discovery.",
        skip_reason="Admin deep scan is held for active/aggressive authorized mode or later discovery.",
    ),
    StepDefinition(
        "backend_scan",
        "Backend API Follow-up Scan",
        http_heavy=True,
        smart_optional=True,
        reason="Backend/API host references were discovered during JavaScript/subdomain analysis.",
        skip_reason="No backend/API hosts were discovered for follow-up scanning.",
    ),
    StepDefinition(
        "cors",
        "CORS Deep Configuration Scan",
        http_heavy=True,
        smart_optional=True,
        reason="CORS headers discovered; deep testing for wildcard+credentials, origin reflection, and dangerous methods is relevant.",
        skip_reason="No CORS headers or API endpoints were detected on the target surface.",
    ),
    StepDefinition(
        "openapi",
        "OpenAPI / Swagger Spec Discovery",
        http_heavy=True,
        smart_optional=True,
        reason="API documentation paths or framework indicators were detected.",
        skip_reason="No API documentation framework or spec file indicators were detected.",
    ),
    StepDefinition(
        "server_leaks",
        "Server Leak & Environment Detection",
        baseline=True,
        reason="Server header analysis, timing metadata, and environment fingerprinting complement every scan.",
    ),
    # ── new in v1.2.0 ─────────────────────────────────
    StepDefinition(
        "api_docs",
        "API Documentation Discovery",
        http_heavy=True,
        smart_optional=True,
        reason="API documentation pages (ASP.NET Help, /docs) can expose all endpoints with full signatures.",
        skip_reason="No API documentation page signal (ASP.NET Help, /docs, /help) was detected.",
    ),
    StepDefinition(
        "email_recon",
        "Email Security & SPF/DMARC Analysis",
        baseline=True,
        reason="Email authentication posture (MX, SPF, DMARC, DKIM) is a foundational security check.",
    ),
    StepDefinition(
        "salesforce",
        "Salesforce Instance Detection",
        http_heavy=True,
        smart_optional=True,
        reason="Salesforce indicators detected in page content, headers, or subdomains.",
        skip_reason="No Salesforce indicators were detected in the page content, headers, or subdomains.",
    ),
    # ── new: Registration Security ─────────────────────
    StepDefinition(
        "registration",
        "Registration Security Analysis",
        http_heavy=True,
        smart_optional=True,
        reason="Registration/Auth endpoints detected; check for OTP bypass and role escalation.",
        skip_reason="No registration or authentication endpoints were discovered on the target.",
    ),
    # ── new: Azure Cloud Recon ─────────────────────────
    StepDefinition(
        "azure_cloud",
        "Azure Cloud Infrastructure Detection",
        baseline=True,
        reason="Azure cloud services (App Service, Blob, Front Door) can expose infrastructure details.",
    ),
    # ── new: Auth Security Scanner ─────────────────────
    StepDefinition(
        "auth_security",
        "Auth Security & PII Leak Scanner",
        http_heavy=True,
        smart_optional=True,
        reason="API endpoints detected; probe for unauthenticated PII leaks and admin endpoint exposure.",
        skip_reason="No API endpoints or authorization signals were detected on the target.",
    ),
]

STEP_BY_KEY = {step.key: step for step in STEP_DEFINITIONS}
STEP_TITLES = {step.key: step.title for step in STEP_DEFINITIONS}
EXECUTION_ORDER = [step.key for step in STEP_DEFINITIONS]
HTTP_HEAVY_STEPS = {step.key for step in STEP_DEFINITIONS if step.http_heavy}
BASELINE_STEPS = {step.key for step in STEP_DEFINITIONS if step.baseline}
ACTIVE_ONLY_STEPS = {step.key for step in STEP_DEFINITIONS if step.active_only}


def planned_total(plan):
    if plan is None:
        return len(EXECUTION_ORDER)
    planned = set(plan)
    planned.add("basic")
    return max(1, sum(1 for key in EXECUTION_ORDER if key in planned))
