import json
import re
from datetime import datetime
from pathlib import Path
from textwrap import wrap

from modules.core.summary import infer_stack


SENSITIVE_KEY_HINTS = (
    "secret", "token", "key", "password", "passwd", "credential",
    "cookie", "authorization", "jwt", "bearer", "client_secret",
    "service_role", "anon_key", "api_key",
)


def redact_results(value, parent_key=""):
    if isinstance(value, dict):
        return {k: redact_results(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_results(item, parent_key) for item in value]

    key = str(parent_key).lower()
    if any(hint in key for hint in SENSITIVE_KEY_HINTS):
        if value in (None, "", [], {}):
            return value
        text = str(value)
        if len(text) <= 10:
            return "[redacted]"
        return f"{text[:6]}...[redacted]"
    return value


def _safe_filename(value):
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', value).strip('_')
    return safe or 'target'


def _count_findings(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(
            _count_findings(v)
            for k, v in value.items()
            if not str(k).startswith('skipped_') and k != 'scan_mode'
        )
    return 0


def _markdown_table(headers, rows):
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        out.append("| " + " | ".join(str(cell).replace("\n", " ") for cell in row) + " |")
    return "\n".join(out)


def _completed(metadata, name):
    completed = metadata.get('completed_result_sections', [])
    return name in completed


def _real_vulnerability_items(vulnerabilities):
    if not isinstance(vulnerabilities, dict):
        return {}
    return {
        finding_type: findings
        for finding_type, findings in vulnerabilities.items()
        if not finding_type.startswith('skipped_')
        and finding_type != 'scan_mode'
        and isinstance(findings, list)
        and findings
    }


def generate_markdown_report(results, domain):
    metadata = results.get('scan_metadata', {})
    basic = results.get('basic', {})
    headers = basic.get('headers', {})
    tech = basic.get('technologies', {})
    stack = infer_stack(results)
    waf = basic.get('waf', [])

    lines = [
        f"# Nexus-REC Security Report: {domain}",
        "",
        "## 1. Executive Summary",
        "",
        f"- Target: `{domain}`",
        f"- Scan mode: `{metadata.get('scan_mode', 'unknown')}`",
        f"- Started at: `{metadata.get('started_at', 'unknown')}`",
    ]
    if metadata.get('stealth'):
        lines.append("- Stealth mode: `enabled`")
    if stack:
        lines.append(f"- Detected stack: {', '.join(stack)}")
    if waf:
        lines.append(f"- WAF/CDN signal: {', '.join(waf)}")
    if tech:
        lines.append(f"- Technologies detected: {len(tech)}")
    lines.append("")

    requested = metadata.get('requested_modules', 'unknown')
    if isinstance(requested, list):
        requested_text = ', '.join(requested)
    else:
        requested_text = str(requested)
    completed = metadata.get('completed_result_sections', [])
    not_selected = metadata.get('not_selected_or_skipped_modules', [])
    coverage_rows = [
        ["Requested modules", requested_text],
        ["Completed result sections", ', '.join(completed) if completed else 'None recorded'],
        ["Not selected / skipped", ', '.join(not_selected) if not_selected else 'None'],
    ]
    lines += ["---", "", "## 2. Scan Coverage", "", _markdown_table(["Item", "Value"], coverage_rows), ""]

    section_num = 3
    smart_reasons = metadata.get('smart_plan_reasons', {})
    smart_skips = metadata.get('smart_skip_reasons', {})
    if smart_reasons or smart_skips:
        decision_rows = []
        for module, reason in smart_reasons.items():
            decision_rows.append([module, "Run", reason])
        for module, reason in smart_skips.items():
            decision_rows.append([module, "Skip", reason])
        if decision_rows:
            lines += [
                "---",
                "",
                f"## {section_num}. Smart Scan Decisions",
                "",
                _markdown_table(["Module", "Decision", "Reason"], decision_rows),
                "",
            ]
            section_num += 1

    if _completed(metadata, 'basic') and tech:
        rows = [[name, source] for name, source in sorted(tech.items())]
        lines += ["---", "", f"## {section_num}. Technologies", "", _markdown_table(["Technology", "Evidence"], rows), ""]
        section_num += 1

    if _completed(metadata, 'basic') and headers:
        rows = []
        for key, value in headers.items():
            if key.startswith('_') or key == 'infra_notes':
                continue
            rows.append([key, value])
        if rows:
            lines += ["---", "", f"## {section_num}. Security Headers", "", _markdown_table(["Header", "Value"], rows), ""]
            section_num += 1

    lines += ["---", "", f"## {section_num}. Findings Overview", ""]
    section_num += 1
    overview_rows = []
    for key, value in sorted(results.items()):
        if key in {'basic', 'scan_metadata', 'detected_stack'}:
            continue
        count = _count_findings(value)
        if count:
            overview_rows.append([key, count])
    if overview_rows:
        lines += [_markdown_table(["Section", "Finding Count"], overview_rows), ""]
    else:
        lines += ["No high-signal findings were recorded in the modules executed for this scan.", ""]

    vulnerabilities = results.get('vulnerabilities', {})
    vuln_items = _real_vulnerability_items(vulnerabilities)
    if _completed(metadata, 'vulnerabilities') and vuln_items:
        lines += ["---", "", f"## {section_num}. Vulnerability Details", ""]
        section_num += 1
        for finding_type, findings in vuln_items.items():
            lines += [f"### {finding_type}", ""]
            for item in findings[:10]:
                if isinstance(item, dict):
                    endpoint = item.get('endpoint', item.get('path', item.get('url', 'N/A')))
                    status = item.get('status', 'N/A')
                    preview = str(item.get('preview', item.get('response', item.get('type', ''))))[:300]
                    lines += [
                        f"- Endpoint: `{endpoint}`",
                        f"  Status: `{status}`",
                        f"  Evidence: {preview or 'N/A'}",
                    ]
                else:
                    lines.append(f"- {item}")
            lines.append("")

    js_data = results.get('js', {})
    amplify_config = js_data.get('amplify_config', {})
    if _completed(metadata, 'js') and amplify_config:
        rows = []
        for key, values in sorted(amplify_config.items()):
            disp = key.replace('aws_', '').replace('_', ' ').title()
            for val in values[:5]:
                rows.append([disp, val])
            if len(values) > 5:
                rows.append([disp, f"+ {len(values)-5} more"])
        lines += ["---", "", f"## {section_num}. JS Analysis — AWS Amplify", "", _markdown_table(["Key", "Value"], rows), ""]
        section_num += 1

    gql_data = results.get('graphql', {})
    appsync_data = gql_data.get('appsync_endpoints', {})
    if _completed(metadata, 'graphql') and appsync_data:
        lines += ["---", "", f"## {section_num}. GraphQL — AWS AppSync Endpoints", ""]
        section_num += 1
        for url, info in appsync_data.items():
            lines += [f"### Endpoint: `{url}`", ""]
            api_keys = info.get('detected_api_keys', [])
            if api_keys:
                for ak in api_keys:
                    lines.append(f"- API Key: `{ak}`")
            auth_results = info.get('auth_header_results', {})
            if auth_results:
                for hdr, hinfo in auth_results.items():
                    err = hinfo.get('error_type', '?')
                    st = hinfo.get('status', '?')
                    lines.append(f"- Auth (`{hdr}`): Status {st} — {err}")
            lines.append("")

    nextjs_data = results.get('nextjs', {})
    manifest_routes = nextjs_data.get('manifest_routes', [])
    if _completed(metadata, 'nextjs') and manifest_routes:
        lines += ["---", "", f"## {section_num}. Next.js — Build Manifest Routes", ""]
        section_num += 1
        public_routes = [r for r in manifest_routes if not any(
            seg.startswith('[') for seg in r.split('/') if seg)]
        dynamic_routes = [r for r in manifest_routes if any(
            seg.startswith('[') for seg in r.split('/') if seg)]
        if public_routes:
            lines += [f"### Static Routes ({len(public_routes)})", ""]
            for pr in public_routes[:20]:
                lines.append(f"- `{pr}`")
            if len(public_routes) > 20:
                lines.append(f"- *... and {len(public_routes)-20} more*")
            lines.append("")
        if dynamic_routes:
            lines += [f"### Dynamic Routes ({len(dynamic_routes)})", ""]
            for dr in dynamic_routes[:10]:
                lines.append(f"- `{dr}`")
            if len(dynamic_routes) > 10:
                lines.append(f"- *... and {len(dynamic_routes)-10} more*")
            lines.append("")

    atlassian_data = results.get('atlassian', {})
    if _completed(metadata, 'atlassian') and atlassian_data.get('detected'):
        lines += ["---", "", f"## {section_num}. Atlassian Stack Recon", ""]
        section_num += 1
        jira = atlassian_data.get('jira', {})
        server_info = jira.get('/rest/api/2/serverInfo', {})
        if server_info.get('version'):
            lines += [
                f"- **Jira Version:** {server_info['version']} ({server_info.get('deployment','?')})",
                f"- **Build:** {server_info.get('build')}",
                f"- **SCM:** {server_info.get('scm','N/A')}",
                f"- **Build Date:** {server_info.get('build_date','N/A')}",
                "",
            ]
        anon = atlassian_data.get('anonymous_access', {})
        if anon:
            lines.append(f"### Anonymous Access ({len(anon)} endpoints)")
            lines.append("")
            for ep, info in anon.items():
                status = info.get('status', '?')
                preview = str(info.get('data', ''))[:120]
                lines.append(f"- `{ep}` (HTTP {status}): {preview}")
            lines.append("")
        dashboard = jira.get('/secure/Dashboard.jspa', {})
        if dashboard.get('internal_message'):
            lines.append("### Dashboard Content Leak")
            lines.append("")
            lines.append(f"> {dashboard['internal_message']}")
            lines.append("")
        if dashboard.get('leaked_project_id'):
            lines.append(f"- **Leaked Project ID:** {dashboard['leaked_project_id']}")
        if dashboard.get('confluence_urls'):
            for cu in dashboard['confluence_urls']:
                lines.append(f"- **Confluence URL:** {cu}")
        azure = atlassian_data.get('azure_app_proxy', {})
        if azure.get('detected'):
            lines += ["", "### Azure App Proxy", ""]
            lines.append(f"- **Tenant ID:** `{azure.get('tenant_id','')}`")
            lines.append(f"- **Data Center:** {azure.get('data_center','')}")
            lines.append(f"- **Service:** {azure.get('service_name','')}")
        saml = atlassian_data.get('saml_sso', {})
        if saml.get('saml_request_found'):
            lines += ["", "### SAML SSO", ""]
            lines.append(f"- **Endpoint:** {saml.get('saml_endpoint','')}")
            if saml.get('environment'):
                lines.append(f"- **Environment:** {saml['environment']}")
        lines.append("")

    # ── CORS Deep Scan ─────────────────────────────────
    cors_data = results.get('cors', {})
    misconfigs = cors_data.get('misconfigurations', [])
    if misconfigs:
        lines += ["---", "", f"## {section_num}. CORS Deep Scan", ""]
        section_num += 1
        cors_rows = []
        for m in misconfigs:
            cors_rows.append([
                m.get('severity', 'LOW'),
                m.get('type', '?'),
                m.get('endpoint', '?'),
                m.get('message', '')[:100],
            ])
        lines += [_markdown_table(["Severity", "Type", "Endpoint", "Description"], cors_rows), ""]
        # Also list tested endpoints
        tested = cors_data.get('tested_endpoints', [])
        if tested:
            lines += [f"**Tested endpoints:** {len(tested)}", ""]

    # ── OpenAPI Spec Discovery ─────────────────────────
    oa_data = results.get('openapi', {})
    if oa_data.get('spec_found'):
        lines += ["---", "", f"## {section_num}. OpenAPI / Swagger Discovery", ""]
        section_num += 1
        for spec in oa_data.get('specs', []):
            parsed = spec.get('parsed', {})
            lines += [f"### Spec: {spec.get('path', '?')}", ""]
            lines += [
                f"- **Title:** {parsed.get('title', '?')}",
                f"- **Version:** {parsed.get('version', '?')}",
                f"- **Total Endpoints:** {parsed.get('total_endpoints', 0)}",
                f"- **File size:** {spec.get('size', 0)} bytes",
                "",
            ]
            unauth = parsed.get('unauthenticated_endpoints', [])
            if unauth:
                unauth_rows = []
                for ep in unauth:
                    unauth_rows.append([ep['method'], ep['path'], ep.get('summary', '')[:60]])
                lines += [f"#### Unauthenticated Endpoints ({len(unauth)})", "",
                          _markdown_table(["Method", "Path", "Summary"], unauth_rows), ""]
            sensitive = parsed.get('sensitive_operations', [])
            if sensitive:
                sens_rows = []
                for sa in sensitive[:10]:
                    sens_rows.append([sa['method'], sa['path'], sa.get('summary', '')[:60]])
                lines += [f"#### Sensitive Operations ({len(sensitive)})", "",
                          _markdown_table(["Method", "Path", "Summary"], sens_rows), ""]

    # ── Server Leak Detection ──────────────────────────
    sl_data = results.get('server_leaks', {})
    leaky = sl_data.get('leaky_headers', {})
    if leaky:
        lines += ["---", "", f"## {section_num}. Server Leak Detection", ""]
        section_num += 1

        header_rows = [[k, v] for k, v in sorted(leaky.items())]
        lines += ["### Leaky Headers", "",
                  _markdown_table(["Header", "Value"], header_rows), ""]

        env = sl_data.get('environment_detected')
        if env:
            lines += [f"- **Environment:** {env} (confidence: {sl_data.get('environment_confidence', '?')})", ""]

        timing = sl_data.get('server_timing_analysis', {})
        internal_params = timing.get('internal_params', [])
        if internal_params:
            param_rows = []
            for p in internal_params:
                param_rows.append([
                    p.get('internal_label', p.get('key', '?')),
                    p.get('key', '?'),
                    p.get('value', ''),
                ])
            lines += ["### Server Timing Analysis", "",
                      _markdown_table(["Label", "Key", "Value"], param_rows), ""]

        versions = sl_data.get('version_disclosures', [])
        if versions:
            ver_rows = []
            for v in versions:
                ver_rows.append([v['header'], v['version']])
            lines += ["### Version Disclosures", "",
                      _markdown_table(["Header", "Version"], ver_rows), ""]

        regions = sl_data.get('internal_regions', [])
        if regions:
            lines += [f"- **Internal Regions:** {', '.join(regions)}", ""]

    # ── API Documentation Discovery ──────────────────────
    api_docs_data = results.get('api_docs', {})
    if _completed(metadata, 'api_docs') and api_docs_data.get('doc_pages'):
        lines += ["---", "", f"## {section_num}. API Documentation Discovery", ""]
        section_num += 1
        lines += [f"- **Doc pages found:** {api_docs_data.get('doc_pages_discovered', 0)}", ""]
        lines += [f"- **Help type:** {api_docs_data.get('help_type', 'generic')}", ""]
        total = api_docs_data.get('total_endpoints_found', 0)
        if total:
            lines += [f"- **Total API endpoints discovered:** {total}", ""]
        aspnet = api_docs_data.get('aspnet_help', {})
        if aspnet:
            controllers = aspnet.get('controllers', [])
            if controllers:
                lines += [f"- **Controllers ({len(controllers)}):** {', '.join(controllers[:15])}", ""]
            unauth = aspnet.get('unauthenticated_endpoints', 0)
            if unauth:
                lines += [f"- **Potentially unauthenticated endpoints:** {unauth}", ""]
        endpoints = api_docs_data.get('endpoints', [])
        if endpoints:
            ep_rows = []
            ep_set = set()
            for ep in endpoints[:50]:
                uri = ep.get('uri', ep) if isinstance(ep, dict) else str(ep)
                method = ep.get('method', 'GET') if isinstance(ep, dict) else ''
                desc = ep.get('description', '') if isinstance(ep, dict) else ''
                if uri not in ep_set:
                    ep_set.add(uri)
                    ep_rows.append([method, uri, desc[:60]])
            if ep_rows:
                lines += ["", "### Discovered Endpoints", "",
                          _markdown_table(["Method", "URI", "Description"], ep_rows), ""]
            if len(endpoints) > len(ep_rows):
                lines += [f"*... and {len(endpoints) - len(ep_rows)} more endpoints in raw JSON*", ""]

    # ── Email Security Recon ────────────────────────────
    email_data = results.get('email_recon', {})
    if _completed(metadata, 'email_recon') and isinstance(email_data, dict):
        has_email_data = any(key in email_data for key in ['mx', 'spf', 'dmarc', 'dkim'])
        if has_email_data:
            lines += ["---", "", f"## {section_num}. Email Security Analysis", ""]
            section_num += 1

            mx = email_data.get('mx', {})
            mx_records = mx.get('records', [])
            if mx_records:
                mx_rows = [[str(m['priority']), m['server']] for m in mx_records]
                lines += ["### MX Records", "", _markdown_table(["Priority", "Server"], mx_rows), ""]
                providers = mx.get('providers', [])
                if providers:
                    lines += [f"- **Email Providers:** {', '.join(providers)}", ""]

            spf = email_data.get('spf', {})
            spf_record = spf.get('record', '')
            if spf_record:
                lines += ["### SPF Record", "",
                          f"- **Record:** `{spf_record}`",
                          f"- **Severity:** {spf.get('severity', '?')}",
                          f"- **Note:** {spf.get('note', '')}", ""]
            else:
                lines += ["### SPF Record", "",
                          "⚠ **SPF record is MISSING** — domain is vulnerable to email spoofing", ""]

            dmarc = email_data.get('dmarc', {})
            dmarc_str = dmarc.get('record', '')
            if dmarc_str:
                lines += ["### DMARC Record", "",
                          f"- **Record:** `{dmarc_str}`",
                          f"- **Policy:** p={dmarc.get('policy', '?')}",
                          f"- **Severity:** {dmarc.get('severity', '?')}",
                          f"- **Note:** {dmarc.get('note', '')}", ""]
                if dmarc.get('rua'):
                    lines += [f"- **Reporting (rua):** `{dmarc['rua']}`", ""]
            else:
                lines += ["### DMARC Record", "",
                          "⚠ **DMARC record is MISSING** — no email authentication enforcement", ""]

            dkim = email_data.get('dkim', {})
            dkim_found = dkim.get('found', [])
            if dkim_found:
                dkim_rows = [[d['selector'], d.get('record_preview', '')[:100]] for d in dkim_found]
                lines += ["### DKIM Records", "", _markdown_table(["Selector", "Record Preview"], dkim_rows), ""]
            else:
                lines += ["### DKIM Records", "",
                          "ℹ No DKIM records found with common selectors", ""]

            summary = email_data.get('security_summary', {})
            score = summary.get('score')
            if score is not None:
                lines += [f"### Email Security Score: {score}/10 ({summary.get('rating', '?')})", ""]
                issues = summary.get('issues', [])
                if issues:
                    for issue in issues:
                        lines += [f"- ⚠ {issue}", ""]
                strengths = summary.get('strengths', [])
                if strengths:
                    for s in strengths:
                        lines += [f"- ✅ {s}", ""]

    # ── Salesforce Detection ──────────────────────────
    sf_data = results.get('salesforce', {})
    if _completed(metadata, 'salesforce') and isinstance(sf_data, dict) and sf_data.get('detected'):
        lines += ["---", "", f"## {section_num}. Salesforce Instance Detection", ""]
        section_num += 1

        header_det = sf_data.get('header_detection', {}).get('headers_found', {})
        if header_det:
            hdr_rows = [[k, v] for k, v in header_det.items()]
            lines += ["### Headers", "", _markdown_table(["Header", "Value"], hdr_rows), ""]

        html_ind = sf_data.get('html_detection', {}).get('indicators', [])
        if html_ind:
            lines += [f"- **HTML Indicators:** {', '.join(html_ind)}", ""]

        subs = sf_data.get('subdomains', {}).get('subdomains', [])
        sf_subs = [s for s in subs if s.get('is_salesforce')]
        if sf_subs:
            sub_rows = [[s['subdomain'], str(s['status'])] for s in sf_subs]
            lines += ["### Salesforce Subdomains", "", _markdown_table(["Subdomain", "Status"], sub_rows), ""]

        versions = sf_data.get('api_versions', {}).get('versions', [])
        if versions:
            ver_rows = [[v.get('version', '?'), str(v.get('status', '?')), v.get('source', '?')] for v in versions]
            lines += ["### API Versions", "", _markdown_table(["Version", "Status", "Source"], ver_rows), ""]

        unauth = sf_data.get('unauth_endpoints', {}).get('accessible_endpoints', [])
        if unauth:
            ua_rows = [[ep.get('url', '?'), str(ep.get('status', '?'))] for ep in unauth]
            lines += ["### Potentially Accessible Endpoints", "",
                      _markdown_table(["URL", "Status"], ua_rows), ""]

    lines += [
        "---",
        "",
        f"## {section_num}. Notes",
        "",
        "- Raw JSON evidence is saved alongside this report.",
        "- If a redacted export was requested, use it for sharing outside the authorized testing team.",
    ]
    return "\n".join(lines) + "\n"


def _pdf_escape(text):
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_simple_pdf(text, output_file):
    objects = []

    def add_object(content):
        objects.append(content)
        return len(objects)

    def clean_inline(value):
        value = re.sub(r'`([^`]*)`', r'\1', value)
        value = value.replace("**", "").replace("*", "")
        return value.strip()

    render_items = []
    table_header_seen = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            render_items.append({"kind": "space"})
            table_header_seen = False
            continue
        if line == "---":
            render_items.append({"kind": "rule"})
            table_header_seen = False
            continue
        if line.startswith("# "):
            render_items.append({"kind": "title", "text": clean_inline(line[2:])})
            table_header_seen = False
            continue
        if line.startswith("## "):
            render_items.append({"kind": "section", "text": clean_inline(line[3:])})
            table_header_seen = False
            continue
        if line.startswith("### "):
            render_items.append({"kind": "subsection", "text": clean_inline(line[4:])})
            table_header_seen = False
            continue
        if line.startswith("|"):
            cells = [clean_inline(cell) for cell in line.strip("|").split("|")]
            if all(set(cell) <= {"-"} for cell in cells):
                continue
            text_line = "  |  ".join(cells)
            kind = "table_header" if not table_header_seen else "table_row"
            table_header_seen = True
            render_items.append({"kind": kind, "text": text_line})
            continue
        if line.startswith("- "):
            render_items.append({"kind": "bullet", "text": clean_inline(line[2:])})
            table_header_seen = False
            continue
        render_items.append({"kind": "body", "text": clean_inline(line)})
        table_header_seen = False

    pages = []
    current = []
    y = 760

    def item_height(kind):
        return {
            "title": 38,
            "section": 30,
            "subsection": 24,
            "table_header": 18,
            "table_row": 16,
            "bullet": 15,
            "rule": 18,
            "space": 10,
        }.get(kind, 15)

    for item in render_items:
        needed = item_height(item["kind"])
        if y - needed < 50:
            pages.append(current)
            current = []
            y = 760
        current.append(item)
        y -= needed
    if current or not pages:
        pages.append(current)

    page_refs = []
    for page in pages:
        stream_lines = []
        y = 760

        def emit(text_value, font="/F1", size=10, x=50, leading=13):
            nonlocal y
            for wrapped in wrap(text_value, width=max(32, int((560 - x) / (size * 0.52)))) or [""]:
                stream_lines.append("BT")
                stream_lines.append(f"{font} {size} Tf")
                stream_lines.append(f"{x} {y} Td")
                stream_lines.append(f"({_pdf_escape(wrapped)}) Tj")
                stream_lines.append("ET")
                y -= leading

        for item in page:
            kind = item["kind"]
            if kind == "space":
                y -= 7
            elif kind == "rule":
                emit("-" * 88, "/F1", 8, 50, 12)
            elif kind == "title":
                emit(item["text"], "/F2", 18, 50, 24)
                emit("=" * 70, "/F1", 8, 50, 14)
            elif kind == "section":
                y -= 4
                emit(item["text"], "/F2", 14, 50, 19)
            elif kind == "subsection":
                emit(item["text"], "/F2", 11, 58, 16)
            elif kind == "table_header":
                emit(item["text"], "/F2", 9, 58, 14)
            elif kind == "table_row":
                emit(item["text"], "/F1", 9, 58, 13)
            elif kind == "bullet":
                emit("- " + item["text"], "/F1", 10, 65, 14)
            else:
                emit(item["text"], "/F1", 10, 50, 14)

        stream = "\n".join(stream_lines).encode("latin-1", "replace")
        content_ref = add_object(
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream"
        )
        page_refs.append((content_ref, None))

    font_ref = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    bold_font_ref = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    pages_ref = len(objects) + len(page_refs) + 1

    fixed_page_refs = []
    for content_ref, _ in page_refs:
        page_ref = add_object(
            f"<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_ref} 0 R /F2 {bold_font_ref} 0 R >> >> "
            f"/Contents {content_ref} 0 R >>"
        )
        fixed_page_refs.append(page_ref)

    kids = " ".join(f"{ref} 0 R" for ref in fixed_page_refs)
    pages_ref_actual = add_object(f"<< /Type /Pages /Kids [{kids}] /Count {len(fixed_page_refs)} >>")
    catalog_ref = add_object(f"<< /Type /Catalog /Pages {pages_ref_actual} 0 R >>")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{idx} 0 obj\n".encode("utf-8"))
        if isinstance(obj, str):
            obj = obj.encode("utf-8")
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref_pos = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_ref} 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode("utf-8")
    )
    output_file.write_bytes(pdf)


def save_scan_results(results, domain, redact_report=False, console=None):
    project_root = Path(__file__).resolve().parents[2]
    output_dir = project_root / 'results'
    output_dir.mkdir(exist_ok=True)

    sanitized_domain = domain.replace(':', '_').replace('/', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_dir = output_dir / f"{timestamp}-{_safe_filename(sanitized_domain)}"
    scan_dir.mkdir(exist_ok=True)
    output_file = scan_dir / "raw_report.json"

    with output_file.open('w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str, ensure_ascii=False)

    markdown_file = scan_dir / "security_report.md"
    markdown = generate_markdown_report(results, domain)
    markdown_file.write_text(markdown, encoding='utf-8')

    pdf_file = scan_dir / "security_report.pdf"
    write_simple_pdf(markdown, pdf_file)

    if console:
        console.print(f"\n[bold green]✓ Report folder: [/bold green]{scan_dir}")
        console.print(f"[bold green]✓ Raw JSON: [/bold green]{output_file}")
        console.print(f"[bold green]✓ Markdown: [/bold green]{markdown_file}")
        console.print(f"[bold green]✓ PDF: [/bold green]{pdf_file}")

    if redact_report:
        redacted_file = scan_dir / "redacted_report.json"
        redacted = redact_results(results)
        redacted.setdefault("scan_metadata", {})["redacted_export"] = True
        with redacted_file.open('w', encoding='utf-8') as f:
            json.dump(redacted, f, indent=2, default=str, ensure_ascii=False)
        if console:
            console.print(f"[bold green]✓ Redacted JSON: [/bold green]{redacted_file}")

    return str(output_file)
