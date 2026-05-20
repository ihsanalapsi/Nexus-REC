import json

from rich.panel import Panel
from rich.table import Table


CATEGORY_GROUPS = {
    'JavaScript frameworks': 'Frontend',
    'UI frameworks': 'Frontend',
    'Font scripts': 'Frontend',
    'JavaScript libraries': 'Frontend',
    'JavaScript graphics': 'Frontend',
    'Static site generator': 'Frontend',
    'Performance': 'Frontend',

    'Web frameworks': 'Backend',
    'Programming languages': 'Backend',

    'Web servers': 'Server',
    'Reverse proxies': 'Server',
    'Load balancers': 'Server',

    'PaaS': 'Hosting',
    'CDN': 'CDN',
    'Hosting': 'Hosting',

    'Databases': 'Database',
    'Database managers': 'Database',

    'Analytics': 'Analytics',
    'Tag managers': 'Analytics',
    'RUM': 'Analytics',

    'Security': 'Security',
    'SSL/TLS certificate authorities': 'Security',
    'Authentication': 'Security',

    'CMS': 'CMS',
    'Ecommerce': 'Ecommerce',
    'Blogs': 'CMS',
}

# Override specific technologies to the right group
TECH_OVERRIDES = {
    'Supabase': 'Database',
    'Firebase': 'Database',
    'MongoDB': 'Database',
    'MySQL': 'Database',
    'PostgreSQL': 'Database',
    'Redis': 'Database',
    'GraphQL': 'API',
    'Apollo': 'API',
    'REST': 'API',
}

def group_technologies(results):
    tech_details = results.get('basic', {}).get('tech_details', {})
    groups = {}
    for tech_name, info in tech_details.items():
        override = TECH_OVERRIDES.get(tech_name)
        if override:
            groups.setdefault(override, []).append(tech_name)
            continue
        cats = info.get('categories', [])
        matched = False
        for cat in cats:
            for key, gname in CATEGORY_GROUPS.items():
                if key.lower() in cat.lower() or cat.lower() in key.lower():
                    groups.setdefault(gname, []).append(tech_name)
                    matched = True
                    break
            if matched:
                break
        if not matched:
            group = cats[0] if cats else 'Other'
            groups.setdefault(group, []).append(tech_name)
    return groups


def as_finding_dict(value):
    if isinstance(value, dict):
        return value
    return {
        'type': type(value).__name__,
        'content': str(value),
        'preview': str(value),
    }


def infer_stack(results):
    stack = list(results.get('detected_stack') or results.get('basic', {}).get('detected_stack') or [])
    tech = results.get('basic', {}).get('technologies', {})
    for name in tech:
        if name in {
            'Next.js', 'React', 'Vue.js', 'Nuxt.js', 'Angular', 'Svelte',
            'Supabase', 'Laravel', 'Django', 'Flask', 'Node.js', 'Node.js/Express',
            'Vercel', 'Cloudflare', 'Firebase', 'GraphQL',
        } and name not in stack:
            stack.append(name)
    return stack

def display_summary(results, domain, console):
    console.print("\n")
    stack = infer_stack(results)
    stack_str = ", ".join(stack) if stack else "Unknown"
    waf = results.get('basic', {}).get('waf', [])
    waf_str = ", ".join(waf) if waf and 'None Detected' not in waf else "None"
    tech = results.get('basic', {}).get('technologies', {})
    tech_count = len(tech)
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] [bold white]{domain}[/bold white]\n"
        f"[bold cyan]Stack:[/bold cyan] [bold white]{stack_str}[/bold white]\n"
        f"[bold cyan]WAF:[/bold cyan] [bold white]{waf_str}[/bold white]\n"
        f"[bold cyan]Technologies:[/bold cyan] [bold white]{tech_count} detected[/bold white]",
        border_style="blue", title="[bold]Target Summary[/bold]"
    ))

    metadata = results.get('scan_metadata', {})
    smart_reasons = metadata.get('smart_plan_reasons', {})
    smart_skips = metadata.get('smart_skip_reasons', {})
    if smart_reasons:
        decision_table = Table(title="[bold]Smart Scan Decisions[/bold]", show_header=True, header_style="bold cyan")
        decision_table.add_column("Module", style="cyan", width=18)
        decision_table.add_column("Decision", style="white")
        for module, reason in list(smart_reasons.items())[:12]:
            decision_table.add_row(module, f"[green]Run[/green] — {reason}")
        if len(smart_reasons) > 12:
            decision_table.add_row("...", f"{len(smart_reasons) - 12} more selected modules recorded in JSON/Markdown")
        for module, reason in list(smart_skips.items())[:6]:
            decision_table.add_row(module, f"[dim]Skip[/dim] — {reason}")
        if len(smart_skips) > 6:
            decision_table.add_row("...", f"{len(smart_skips) - 6} more skipped modules recorded in JSON/Markdown")
        console.print(decision_table)

    groups = group_technologies(results)
    if groups:
        group_table = Table(title="[bold]Technology Breakdown[/bold]", show_header=True, header_style="bold green")
        group_table.add_column("Layer", style="cyan")
        group_table.add_column("Technologies", style="white")
        ordered = ['Frontend', 'Backend', 'Server', 'Database',
                   'Hosting', 'CDN', 'Security', 'Analytics', 'CMS', 'Ecommerce']
        for g in ordered:
            if g in groups:
                techs_str = ', '.join(groups[g])
                group_table.add_row(g, techs_str)
        for g, techs in groups.items():
            if g not in ordered:
                group_table.add_row(g, ', '.join(techs))
        console.print(group_table)

    table = Table(title="[bold]Security Headers Analysis[/bold]", show_header=True, header_style="bold magenta")
    table.add_column("Security Rule", style="cyan")
    table.add_column("Status", style="white")
    headers = results.get('basic', {}).get('headers', {})
    if headers:
        for h, v in headers.items():
            if h.startswith('_') or h == 'infra_notes':
                continue
            if v in ['MISSING', False, None]:
                color = "[red]"
            elif v in [True, 'ENABLED']:
                color = "[green]"
            else:
                color = "[yellow]"
            table.add_row(h, f"{color}{v}[/]")
    else:
        table.add_row("N/A", "[red]Failed to fetch headers[/red]")
    console.print(table)
    infra_notes = headers.get('infra_notes', [])
    if infra_notes:
        console.print(f"\n[bold yellow]⚠ Infrastructure Notes:[/bold yellow]")
        for note in infra_notes:
            console.print(f"  [yellow]{note}[/yellow]")

    sub_data = results.get('subdomain', {})
    subs = sub_data.get('subdomains', [])
    if subs:
        sub_table = Table(title=f"[bold]Subdomains Found ({len(subs)})[/bold]", show_header=True, header_style="bold cyan")
        sub_table.add_column("Subdomain", style="cyan")
        sub_table.add_column("IP", style="white")
        sub_table.add_column("Status", style="yellow")
        for s in subs[:15]:
            status = s.get('http_status', 'N/A')
            status_str = f"[green]{status}[/]" if status in [200, 301, 302] else f"[yellow]{status}[/]"
            sub_table.add_row(s.get('subdomain', ''), s.get('ip', ''), status_str)
        if len(subs) > 15:
            sub_table.add_row(f"... and {len(subs)-15} more", "", "")
        console.print(sub_table)

    cloud_data = results.get('cloud', {})
    buckets = cloud_data.get('s3_buckets', [])
    if buckets:
        console.print(f"[bold red]⚠ Open S3 Buckets: {len(buckets)}[/bold red]")
        for b in buckets:
            mark = "[red]PUBLIC[/red]" if b.get('public') else "[yellow]RESTRICTED[/yellow]"
            console.print(f"  {mark} {b['url']}")
    cf = cloud_data.get('cloudfront', {})
    if cf.get('detected'):
        console.print(f"  [yellow]CloudFront Distribution Detected[/yellow]")

    sub_data = results.get('subdomain', {})
    backends = sub_data.get('backend_discovered', [])
    if backends:
        console.print(f"\n[bold yellow]⚡ Backend Servers Discovered ({len(backends)}):[/bold yellow]")
        for b in backends:
            ip_str = f"({b['ip']})" if b['ip'] != 'unresolved' else "(unresolved)"
            console.print(f"  [dim]- [/dim][green]{b['url']}[/green] {ip_str} [dim]{b['source']}[/dim]")

    related = sub_data.get('related_domains', {})
    related_list = related.get('discovered', [])
    if related_list:
        console.print(f"\n[bold yellow]🔗 Related Domains ({len(related_list)}):[/bold yellow]")
        for rd in related_list:
            console.print(f"  [dim]- [/dim][cyan]{rd}[/cyan]")

    js_data = results.get('js', {})
    apis = js_data.get('extracted_apis', [])
    if apis:
        console.print(f"\n[bold green]Extracted API Endpoints ({len(apis)}):[/bold green]")
        for a in apis[:10]:
            console.print(f"  [dim]- [/dim][white]{a}[/white]")
        if len(apis) > 10:
            console.print(f"  [dim]... and {len(apis)-10} more[/dim]")

    tokens = js_data.get('potential_tokens', [])
    if tokens:
        console.print(f"\n[bold yellow]Potential Secrets/Tokens Found: {len(tokens)}[/bold yellow]")
        for t in tokens[:5]:
            console.print(f"  [dim]- [/dim][red]{t[:50]}[/red]")
        if len(tokens) > 5:
            console.print(f"  [dim]... and {len(tokens)-5} more[/dim]")

    amplify_config = js_data.get('amplify_config', {})
    if amplify_config:
        console.print(f"\n[bold magenta]☁️ AWS Amplify Config Exposed ({len(amplify_config)} keys):[/bold magenta]")
        for key, values in sorted(amplify_config.items()):
            display_key = key.replace('aws_', '').replace('_', ' ').title()
            for val in values[:3]:
                console.print(f"  [cyan]{display_key}:[/cyan] {val}")
            if len(values) > 3:
                console.print(f"    [dim]+ {len(values)-3} more values[/dim]")

    gql_data = results.get('graphql', {})
    introspection = gql_data.get('introspection', {})
    for url, status in introspection.items():
        if status.get('introspection_enabled'):
            console.print(f"[bold red]⚠ GraphQL Introspection ENABLED at:[/bold red] {url}")
            if status.get('sensitive_count', 0) > 0:
                console.print(f"  [bold red]Sensitive types exposed: {status['sensitive_count']}[/bold red]")

    # GraphQL Error-Based Schema Leak
    err_leak = gql_data.get('error_schema_leak', {})
    if err_leak:
        for url, leaks in err_leak.items():
            queries = leaks.get('queries_discovered', [])
            mutations = leaks.get('mutations_discovered', [])
            if queries or mutations:
                console.print(f"\n[bold yellow]⚡ GraphQL Schema Harvested via Validation Errors at:[/bold yellow] {url}")
                if queries:
                    q_str = ', '.join(q['name'] for q in queries[:15])
                    console.print(f"  [cyan]Queries discovered ({len(queries)}):[/cyan] {q_str}")
                if mutations:
                    m_str = ', '.join(m['name'] for m in mutations[:15])
                    console.print(f"  [cyan]Mutations discovered ({len(mutations)}):[/cyan] {m_str}")

    # GraphQL CSRF Protection
    csrf_prot = gql_data.get('csrf_protection', {})
    if csrf_prot:
        for url, tests in csrf_prot.items():
            vuln_tests = []
            for test_name, res in tests.items():
                if not res.get('blocked', True):
                    vuln_tests.append(test_name)
            if vuln_tests:
                console.print(f"  [bold red]⚠ GraphQL CSRF Vulnerability at {url}![/bold red]")
                console.print(f"    Apollo Require Preflight / CSRF protection not active for: {', '.join(vuln_tests)}")

    # ── AWS AppSync endpoint findings ──
    appsync_data = gql_data.get('appsync_endpoints', {})
    if appsync_data:
        console.print(f"\n[bold magenta]⚡ AWS AppSync Endpoints ({len(appsync_data)}):[/bold magenta]")
        for url, info in appsync_data.items():
            console.print(f"  [cyan]Endpoint:[/cyan] {url}")
            api_keys = info.get('detected_api_keys', [])
            if api_keys:
                for ak in api_keys:
                    console.print(f"    [yellow]🔑 API Key:[/yellow] {ak}")
            auth_results = info.get('auth_header_results', {})
            if auth_results:
                for hdr, hinfo in auth_results.items():
                    err = hinfo.get('error_type', '?')
                    st = hinfo.get('status', '?')
                    if err != 'none':
                        console.print(f"    [dim]Auth ({hdr}):[/dim] Status {st} — {err}")

    vuln_data = dict(results.get('vulnerabilities', {}))
    total_vulns = sum(len(v) for v in vuln_data.values() if isinstance(v, list))
    homepage_len = results.get('basic', {}).get('content_length', 0)

    # Mass Assignment findings
    mass_assign = vuln_data.get('mass_assignment', [])
    if mass_assign:
        ma_table = Table(title=f"[bold red]⚠ Mass Assignment Vulnerabilities ({len(mass_assign)})[/bold red]",
                        show_header=True, header_style="bold red")
        ma_table.add_column("Endpoint", style="cyan", width=30)
        ma_table.add_column("Status", style="yellow", width=8)
        ma_table.add_column("Payload", style="white", width=50)
        for ma in mass_assign:
            payload_str = ', '.join(f"{k}={v}" for k, v in ma.get('payload', {}).items())
            ma_table.add_row(ma.get('endpoint', '?'), str(ma.get('status', '?')), payload_str[:48])
        console.print(ma_table)

    # Payment Data Leak findings
    payment_leaks = vuln_data.get('payment_data_leak', [])
    if payment_leaks:
        pl_table = Table(title=f"[bold red]💳 Payment Data Leaks ({len(payment_leaks)})[/bold red]",
                        show_header=True, header_style="bold red")
        pl_table.add_column("Endpoint", style="cyan", width=28)
        pl_table.add_column("Status", style="yellow", width=6)
        pl_table.add_column("Size", style="white", width=8)
        pl_table.add_column("Payment Sigs", style="red", width=30)
        pl_table.add_column("PII", style="yellow", width=20)
        for pl in payment_leaks:
            pay_sigs = ', '.join(pl.get('payment_signatures', [])[:4])
            pii_sigs = ', '.join(pl.get('pii_signatures', [])[:4])
            pl_table.add_row(
                pl.get('endpoint', '?'),
                str(pl.get('status', '?')),
                str(pl.get('size', '?')),
                pay_sigs,
                pii_sigs
            )
            # Show classification details if available
            cls = pl.get('classification', {})
            if cls:
                methods = cls.get('payment_methods_detected', [])
                if methods:
                    console.print(f"    [dim]Payment Methods: {', '.join(methods)}[/dim]")
                if cls.get('has_client_secret'):
                    console.print(f"    [bold red]⚠ client_secret EXPOSED![/bold red]")
                if cls.get('is_test_mode') is False:
                    console.print(f"    [bold red]⚠ LIVE MODE (not test!)[/bold red]")
                pii = cls.get('pii_fields', [])
                if pii:
                    console.print(f"    [yellow]PII Fields: {', '.join(pii)}[/yellow]")
                records = cls.get('total_records', 0)
                if records:
                    console.print(f"    [dim]Records: {records}[/dim]")
        console.print(pl_table)

    # Separate HTTP_METHODS (different schema) from other vulns
    method_findings = vuln_data.pop('http_methods', []) if isinstance(vuln_data.get('http_methods'), list) else []
    real_vulns = {
        k: v for k, v in vuln_data.items()
        if isinstance(v, list) and v and not k.startswith('skipped_')
    }

    if method_findings:
        mtable = Table(
            title=f"[bold yellow]HTTP Methods Discovered ({len(method_findings)})[/bold yellow]",
            show_header=True, header_style="bold yellow"
        )
        mtable.add_column("Path", style="cyan", width=40)
        mtable.add_column("Allowed Methods", style="white", width=40)
        mtable.add_column("Notes", style="dim", width=35)
        for m in method_findings:
            path = m.get('path', '?')
            methods = ', '.join(m.get('allowed_methods', []))
            non_get = m.get('non_get_methods', [])
            is_spa = m.get('is_spa_catchall', False)
            if is_spa:
                note = '[yellow]⚠ SPA catchall[/yellow]'
            elif non_get:
                note = f'[yellow]POST/PUT/DELETE[/yellow]'
            else:
                note = 'GET only'
            mtable.add_row(path, methods, note)
        console.print(mtable)

    if real_vulns:
        for vtype, vlist in real_vulns.items():
            vuln_table = Table(
                title=f"[bold red]{vtype.upper()} ({len(vlist)})[/bold red]",
                show_header=True, header_style="bold red"
            )
            vuln_table.add_column("Endpoint", style="cyan", width=40)
            vuln_table.add_column("Status", style="yellow", width=8)
            vuln_table.add_column("Size", style="white", width=8)
            vuln_table.add_column("Type/Content", style="dim", width=40)
            vuln_table.add_column("Assessment", style="bold", width=20)

            for item in vlist[:10]:
                v = as_finding_dict(item)
                ep = v.get('endpoint', v.get('path', ''))
                if not ep:
                    ep = v.get('url', v.get('content', ''))
                st = v.get('status', '?')
                sz = v.get('size', '?')
                ct = str(v.get('content_type', v.get('type', v.get('mode', ''))))
                preview = str(v.get('preview', v.get('content', '')))[:100].lower()

                if '<!doctype html>' in preview or '<html' in preview:
                    is_spa = 'SPA page' if sz == homepage_len else 'HTML page'
                    assessment = f'[yellow]⚠ {is_spa}[/yellow]'
                elif 'application/json' in ct or '{' in preview[:10]:
                    assessment = '[green]✅ Real API[/green]'
                elif 'redirect' in str(st).lower():
                    assessment = '[blue]↪ Redirect[/blue]'
                elif st in [401, 403]:
                    assessment = '[red]🔒 Protected[/red]'
                else:
                    assessment = f'[yellow]⚠ ?[/yellow]'
                vuln_table.add_row(ep, str(st), str(sz), ct[:38], assessment)

            if len(vlist) > 10:
                vuln_table.add_row(f"... and {len(vlist)-10} more", "", "", "", "")
            console.print(vuln_table)

        total_spa = 0
        for vtype, vlist in real_vulns.items():
            for item in vlist:
                v = as_finding_dict(item)
                if v.get('size') == homepage_len:
                    total_spa += 1
        if total_spa > 0:
            console.print(f"  [dim]ℹ {total_spa}/{total_vulns} findings are SPA catchall pages "
                          f"(same content as homepage), likely false positives[/dim]")

    # Restore http_methods for completeness
    vuln_data['http_methods'] = method_findings

    secrets_data = results.get('secrets', {})
    exposed = secrets_data.get('exposed_files', [])
    if exposed:
        console.print(f"\n[bold red]Exposed Sensitive Files: {len(exposed)}[/bold red]")
        for f in exposed[:5]:
            console.print(f"  [red]{f['path']}[/red] -> Status: {f['status']} ({f['size']} bytes)")
    blocked_paths = secrets_data.get('blocked_paths', [])
    if blocked_paths:
        console.print(f"\n[dim]🚫 Blocked Paths ({len(blocked_paths)}): 403 — edge/WAF protection active[/dim]")

    # Internal machine names (from basic or secrets)
    basic_data = results.get('basic', {})
    infra = basic_data.get('infra_findings', {}) or secrets_data.get('infra_attrs', {})
    machines = infra.get('internal_machine_names', [])
    if machines:
        console.print(f"\n[bold red]🖥 Internal Machine Names Exposed:[/bold red]")
        for m in machines:
            console.print(f"  [yellow]{m}[/yellow]")
    data_attrs = infra.get('infra_data_attrs', [])
    if data_attrs:
        console.print(f"\n[bold yellow]📋 Infrastructure Data Attributes:[/bold yellow]")
        for k, v in data_attrs[:10]:
            console.print(f"  [cyan]{k}[/cyan] = [white]{v}[/white]")
    cors_warning = infra.get('cors_warning')
    if cors_warning:
        console.print(f"\n[bold yellow]⚠ CORS Misconfiguration:[/bold yellow]")
        console.print(f"  {cors_warning}")

    # Cookie Analysis
    cookie_data = results.get('cookies', {})
    cookie_analysis = cookie_data.get('cookies', {})
    cred_leak = []  # default — populated below if cookies module ran
    if cookie_analysis:
        total_cookies = cookie_analysis.get('total_cookies', 0)
        missing_secure = cookie_analysis.get('missing_secure', [])
        missing_httponly = cookie_analysis.get('missing_httponly', [])
        jwt_found = cookie_analysis.get('potential_jwt', [])
        cred_leak = cookie_analysis.get('credential_leak', [])
        if total_cookies > 0:
            cookie_table = Table(title=f"[bold]Cookie Security Analysis ({total_cookies} cookies)[/bold]",
                                 show_header=True, header_style="bold yellow")
            cookie_table.add_column("Check", style="cyan")
            cookie_table.add_column("Result", style="white")
            cookie_table.add_row("Cookies Found", str(total_cookies))
            secure_str = f"[green]{len(missing_secure)} cookies missing Secure[/green]" if not missing_secure else f"[red]{', '.join(missing_secure)} missing Secure[/red]"
            cookie_table.add_row("Secure Flag", secure_str)
            http_str = f"[green]{len(missing_httponly)} cookies missing HttpOnly[/green]" if not missing_httponly else f"[red]{', '.join(missing_httponly)} missing HttpOnly[/red]"
            cookie_table.add_row("HttpOnly Flag", http_str)
            cookie_table.add_row("JWT Cookies", str(len(jwt_found)))
            cookie_table.add_row("Credential Leaks", f"[red]{len(cred_leak)}[/red]" if cred_leak else "[green]0[/green]")
            console.print(cookie_table)

        if jwt_found:
            console.print(f"\n[bold yellow]⚡ JWT Cookies Decoded:[/bold yellow]")
            for j in jwt_found:
                pay = j.get('payload', {})
                console.print(f"  [cyan]{j['cookie_name']}[/cyan]: {pay}")
                if j.get('has_cred_fields'):
                    console.print(f"    [red]⚠ Contains credential fields![/red]")
                if j.get('hs256_cracked'):
                    console.print(f"    [bold red]🔓 HS256 CRACKED![/bold red] Secret: [green]{j['hs256_secret']}[/green]")

        if cred_leak:
            console.print(f"\n[bold red]⚠ Credential Leakage in Cookies:[/bold red]")
            for c in cred_leak:
                console.print(f"  [red]{c['type']}[/red] in [{c['cookie_name']}]")

    # CSRF Analysis
    csrf = cookie_data.get('csrf_analysis', {})
    if csrf:
        csrf_status = "[green]Protected[/green]" if csrf.get('csrf_protected') else "[red]MISSING[/red]"
        console.print(f"\n[bold]CSRF Protection:[/bold] {csrf_status}")

    # DNS / SSL Analysis
    dns_data = results.get('dns', {})
    wildcard = dns_data.get('wildcard_dns', {})
    if wildcard.get('wildcard_detected'):
        console.print(f"\n[bold yellow]⚠ Wildcard DNS Detected:[/bold yellow]")
        console.print(f"  {wildcard.get('note', '')}")
        console.print(f"  Base IP: [cyan]{wildcard.get('base_ip', 'N/A')}[/cyan]")
        console.print(f"  Matched: {wildcard.get('total_matched', 0)}/{wildcard.get('total_tested', 0)} test subdomains")

    ssl_data = dns_data.get('ssl_cert', {})
    if ssl_data.get('subject'):
        console.print(f"\n[bold cyan]🔒 SSL Certificate:[/bold cyan]")
        console.print(f"  Subject: [white]{ssl_data.get('subject', 'N/A')}[/white]")
        console.print(f"  Issuer: [dim]{ssl_data.get('issuer', 'N/A')}[/dim]")
        if ssl_data.get('not_after'):
            console.print(f"  Expires: [yellow]{ssl_data['not_after']}[/yellow]")
        if ssl_data.get('is_wildcard'):
            console.print(f"  [yellow]Wildcard Cert: {', '.join(ssl_data.get('subject_alt_names', []))}[/yellow]")

    ports = dns_data.get('open_ports', [])
    if ports:
        port_str = ', '.join(f"{p['port']}/{p['service']}" for p in ports)
        console.print(f"\n[bold cyan]📡 Open Ports ({len(ports)}):[/bold cyan] {port_str}")

    # Endpoint Discovery
    ep_data = results.get('endpoints', {})
    login_forms = ep_data.get('login_forms', [])
    if login_forms:
        console.print(f"\n[bold yellow]🔑 Login Forms Found ({len(login_forms)}):[/bold yellow]")
        for lf in login_forms:
            csrf_mark = "[green]CSRF✅[/green]" if lf.get('has_csrf') else "[red]No CSRF❌[/red]"
            console.print(f"  {lf['path']} ({lf['status']}, {csrf_mark})")

    http_methods = ep_data.get('http_methods', [])
    interesting_methods = [m for m in http_methods if m.get('interesting')]
    if interesting_methods:
        console.print(f"\n[bold yellow]⚡ Non-GET Endpoints ({len(interesting_methods)}):[/bold yellow]")
        for m in interesting_methods:
            meths = ', '.join(m.get('allowed_methods', []))
            console.print(f"  {m['path']}: {meths}")

    api_redirects = ep_data.get('api_redirects', [])
    insecure_redirects = [r for r in api_redirects if r.get('warn_http')]
    if insecure_redirects:
        console.print(f"\n[bold red]⚠ API Redirects to HTTP:[/bold red]")
        for r in insecure_redirects:
            console.print(f"  {r['path']} -> [red]{r['redirect_to'][:80]}[/red]")

    platforms = ep_data.get('platform_endpoints', {})
    if platforms:
        console.print(f"\n[bold cyan]🏗️ Platform Endpoints:[/bold cyan]")
        for plat, info in platforms.items():
            count = info.get('endpoint_count', 0)
            ep_list = ', '.join(f"{e['path']}({e['status']})" for e in info.get('endpoints_found', []))
            if ep_list:
                console.print(f"  [cyan]{plat}:[/cyan] {ep_list}")

    # jQuery vuln warnings
    jq_warnings = basic_data.get('jquery_warnings', []) or js_data.get('jquery_vulns', [])
    if jq_warnings:
        console.print(f"\n[bold red]⚠ jQuery Vulnerability Detected:[/bold red]")
        for w in jq_warnings:
            cves = f" ({', '.join(w.get('cve_list', []))})" if w.get('cve_list') else ''
            console.print(f"  [red]{w['library']} {w['version']}[/red]{cves}")
            console.print(f"  [dim]{w['note']}[/dim]")

    # Mobile apps
    mob_apps = js_data.get('mobile_apps', {})
    if mob_apps:
        console.print(f"\n[bold cyan]📱 Mobile Apps Detected:[/bold cyan]")
        for k, v in mob_apps.items():
            if isinstance(v, list):
                console.print(f"  [dim]{k}:[/dim] {', '.join(v)}")
            else:
                console.print(f"  [dim]{k}:[/dim] {v}")
    # CF Email decode
    cfemail = secrets_data.get('cfemail', {})
    if cfemail.get('decoded'):
        console.print(f"\n[bold cyan]📧 Cloudflare Protected Email Decoded:[/bold cyan]")
        console.print(f"  [green]{cfemail['decoded']}[/green]")

    # Search schema
    search_schema = secrets_data.get('search_schema', {})
    if search_schema.get('search_action'):
        console.print(f"\n[bold cyan]🔍 Search Schema Detected:[/bold cyan]")
        sa = search_schema['search_action']
        console.print(f"  Target: [white]{sa.get('target', 'N/A')}[/white]")
        console.print(f"  Query Input: [white]{sa.get('query_input', 'N/A')}[/white]")

    # NetScaler detection
    netscaler_data = cloud_data.get('netscaler', {})
    if netscaler_data.get('netscaler_detected'):
        console.print(f"\n[bold yellow]⚙ NetScaler/Load Balancer Detected:[/bold yellow]")
        for k, v in netscaler_data.items():
            console.print(f"  [dim]{k}:[/dim] {v}")

    # Login endpoint analysis summary
    login_data = vuln_data.get('login_endpoint', {})
    if login_data:
        if login_data.get('credential_in_cookie'):
            console.print(f"\n[bold red]🔴 CREDENTIAL LEAK IN COOKIE: Login stores user:pass in JWT cookie![/bold red]")
        if login_data.get('accepts_credentials'):
            console.print(f"[bold yellow]⚠ Login accepts arbitrary credentials at {login_data.get('endpoint', '?')}[/bold yellow]")

    # Cookie credential leak summary
    if cred_leak:
        console.print(f"\n[bold red]🔴 Total Cookie Credential Leaks: {len(cred_leak)}[/bold red]")

    # Backend scan results
    backend_scan = results.get('backend_scan', {})
    if backend_scan and isinstance(backend_scan, dict):
        backend_items = backend_scan.get('scanned_backends', backend_scan)
        if not backend_items:
            backend_items = {}
    if backend_scan and isinstance(backend_scan, dict) and backend_items:
        btable = Table(title=f"[bold cyan]⚡ Backend API Scan ({len(backend_items)})[/bold cyan]",
                      show_header=True, header_style="bold cyan")
        btable.add_column("Backend URL", style="cyan", width=45)
        btable.add_column("Status", style="yellow", width=8)
        btable.add_column("Server", style="white", width=15)
        btable.add_column("Type", style="dim", width=20)
        btable.add_column("APIs Found", style="green", width=15)
        for b_url, b_info in backend_items.items():
            st = b_info.get('status', b_info.get('error', '?'))
            sv = b_info.get('server', '')
            ct = b_info.get('content_type', '')[:20]
            apis = b_info.get('api_endpoints', [])
            api_str = ', '.join(f"{a['path']}({a['status']})" for a in apis) if apis else '—'
            btable.add_row(b_url, str(st), sv, ct, api_str)
        console.print(btable)

    # Backend IP Discovery (from subdomain IP redirect probing)
    ip_disc = results.get('backend_ip_discovery', [])
    if ip_disc:
        console.print(f"\n[bold yellow]🔍 Backend IP Discovery ({len(ip_disc)}):[/bold yellow]")
        for d in ip_disc:
            console.print(f"  [cyan]{d['ip']}[/cyan] → [green]{d.get('redirect_url', 'N/A')}[/green]")
            if d.get('backend_domain'):
                console.print(f"    [dim]Domain: {d['backend_domain']}[/dim]")

    # ── Payment Gateway Insights ──
    pg_data = results.get('payment_gateway', {})
    pg_has_findings = any(bool(v) for v in pg_data.values()) if isinstance(pg_data, dict) else bool(pg_data)
    if pg_data and pg_has_findings:
        console.print("\n[bold magenta]💳 Payment Gateway Insights:[/bold magenta]")
        csp_gateways = pg_data.get('csp_analysis', {})
        if csp_gateways:
            pg_table = Table(title="[bold]Gateways Detected (CSP)[/bold]",
                            show_header=True, header_style="bold green")
            pg_table.add_column("Provider", style="cyan", width=15)
            pg_table.add_column("Domains", style="white", width=40)
            pg_table.add_column("CSP Directives", style="dim", width=30)
            for gw_name, gw_info in csp_gateways.items():
                domains = ', '.join(gw_info.get('domains', []))
                directives = ', '.join(gw_info.get('directives', []))
                pg_table.add_row(gw_name.title(), domains, directives)
            console.print(pg_table)

        payment_keys = pg_data.get('payment_keys', {})
        if payment_keys:
            for provider, keys in payment_keys.items():
                for k in keys:
                    if isinstance(k, dict):
                        mode = k.get('mode', '?')
                        ktype = k.get('type', '?')
                        kval = k.get('key', '?')
                        color = "[red]" if ktype == 'secret' or mode == 'live' else "[yellow]"
                        console.print(f"  {color}🔑 {provider.title()} Key:[/{color[1:]} {kval} ({mode}/{ktype})")
                    else:
                        console.print(f"  [dim]🔑 {provider}: {k}[/dim]")

        webhooks = pg_data.get('webhooks', [])
        if webhooks:
            console.print(f"  [yellow]🪝 Webhook References ({len(webhooks)}):[/yellow]")
            for wh in webhooks[:5]:
                console.print(f"    [dim]{wh}[/dim]")

    # ── Stack-Specific Insights (Laravel / Next.js) ──
    laravel_data = results.get('laravel', {})
    if laravel_data:
        console.print("\n[bold magenta]💎 Laravel Insights:[/bold magenta]")

        # API Debug Leaks
        api_leaks = laravel_data.get('api_debug_check', [])
        if api_leaks:
            leak_table = Table(title="[bold red]⚠ API Debug Leaks (Stack Traces Exposed)[/bold red]", 
                              show_header=True, header_style="bold red")
            leak_table.add_column("Endpoint", style="cyan")
            leak_table.add_column("Status", style="yellow")
            leak_table.add_column("Path Leak", style="red")
            for leak in api_leaks:
                path_leak = "[bold red]YES[/bold red]" if leak.get('server_path_leaked') else "No"
                leak_table.add_row(leak['endpoint'], str(leak['status']), path_leak)
            console.print(leak_table)

        # Boost Package
        boost = laravel_data.get('boost_package', {})
        if boost.get('detected'):
            status = "[red]INJECTABLE[/red]" if boost.get('injectable') else "[green]Detected[/green]"
            console.print(f"  [yellow]📦 Package:[/yellow] {boost.get('package')} — {status}")
            if boost.get('endpoint'):
                console.print(f"    [dim]Endpoint: {boost['endpoint']}[/dim]")

        # WAF & Reverse Proxy
        waf_list = laravel_data.get('waf', [])
        if 'Imunify360' in waf_list:
            console.print(f"  [bold red]🛡️ WAF Detected:[/bold red] Imunify360 (Aggressive Blocking Active)")

        rev_proxy = laravel_data.get('reverse_proxy')
        if rev_proxy == 'OpenResty':
            console.print(f"  [bold cyan]🔄 Reverse Proxy:[/bold cyan] OpenResty (Nginx + Lua)")

        # Server Detection
        server_detected = laravel_data.get('server')
        if server_detected:
            console.print(f"  [cyan]🖥 Server:[/cyan] {server_detected}")
        if laravel_data.get('xsrf_token_detected'):
            console.print(f"  [green]✅ XSRF-TOKEN Cookie:[/green] Detected (Laravel confirmed)")

        # Coolify Detection
        coolify = laravel_data.get('coolify', {})
        if coolify.get('detected'):
            inds = coolify.get('indicators', [])
            ind_str = ', '.join(inds) if inds else 'detected'
            console.print(f"  [yellow]🐳 Coolify:[/yellow] Detected ({ind_str})")
            health = coolify.get('health_data', {})
            if health:
                health_str = json.dumps(health)[:100]
                console.print(f"    [dim]/api/v1/health:[/dim] {health_str}")

        # Routes & Inertia
        if laravel_data.get('routes_exposed'):
            console.print(f"  [green]🛣️ Routes:[/green] {len(laravel_data.get('routes', []))} endpoints exposed via window.routes")

        inertia = laravel_data.get('inertia', {})
        if inertia.get('detected'):
            ver = inertia.get('version', 'Unknown')
            console.print(f"  [cyan]⚛️ Inertia.js:[/cyan] Detected (Version: {ver})")

    nextjs_data = results.get('nextjs', {})
    if nextjs_data:
        console.print("\n[bold magenta]💎 Next.js Insights:[/bold magenta]")
        if nextjs_data.get('version'):
            console.print(f"  [cyan]🚀 Version:[/cyan] {nextjs_data['version']}")
        if nextjs_data.get('bundler'):
            console.print(f"  [cyan]📦 Bundler:[/cyan] {nextjs_data['bundler']}")
        if nextjs_data.get('build_id'):
            console.print(f"  [dim]Build ID: {nextjs_data['build_id']}[/dim]")
        if nextjs_data.get('x_powered_by'):
            console.print(f"  [dim]X-Powered-By:[/dim] {nextjs_data['x_powered_by']}")
        if nextjs_data.get('middleware_rewrite'):
            console.print(f"  [yellow]🔄 Middleware Rewrite:[/yellow] {nextjs_data['middleware_rewrite']}")
        if nextjs_data.get('locale'):
            console.print(f"  [cyan]🌍 Default Locale:[/cyan] {nextjs_data['locale']}")
        if nextjs_data.get('sentry_detected'):
            console.print(f"  [cyan]🎯 Sentry Tracking:[/cyan] Detected on client-side")
        if nextjs_data.get('preloaded_assets'):
            console.print(f"  [cyan]⚡ Preloaded Assets:[/cyan] {nextjs_data['preloaded_assets']} assets preloaded in Link header")

        static_subs = nextjs_data.get('static_subdomains', [])
        if static_subs:
            console.print(f"  [cyan]☁️ Static Asset Subdomains ({len(static_subs)}):[/cyan] {', '.join(static_subs)}")

        if nextjs_data.get('middleware_bypass'):
            details = nextjs_data.get('middleware_details', {})
            console.print(f"  [bold red]⚠ CRITICAL: Middleware Bypass Detected![/bold red]")
            console.print(f"    [dim]Path: {details.get('path')} | Payload: {details.get('payload')}[/dim]")

        leaks = nextjs_data.get('leaks', [])
        if leaks:
            for leak in leaks:
                console.print(f"  [yellow]⚠ Leak:[/yellow] {leak}")

        manifest_routes = nextjs_data.get('manifest_routes', [])
        if manifest_routes:
            console.print(f"  [green]🗺️ Routes from Build Manifest:[/green] {len(manifest_routes)} total")
            public_routes = [r for r in manifest_routes if not any(
                seg.startswith('[') for seg in r.split('/') if seg)]
            dynamic_routes = [r for r in manifest_routes if any(
                seg.startswith('[') for seg in r.split('/') if seg)]
            if public_routes:
                console.print(f"    [cyan]Static Routes:[/cyan]")
                for pr in public_routes[:10]:
                    console.print(f"      [dim]- {pr}[/dim]")
                if len(public_routes) > 10:
                    console.print(f"      [dim]... and {len(public_routes)-10} more[/dim]")
            if dynamic_routes:
                console.print(f"    [yellow]Dynamic Routes:[/yellow] {len(dynamic_routes)}")
                for dr in dynamic_routes[:5]:
                    console.print(f"      [dim]- {dr}[/dim]")
                if len(dynamic_routes) > 5:
                    console.print(f"      [dim]... and {len(dynamic_routes)-5} more[/dim]")

        api_chunks = nextjs_data.get('api_routes_from_chunks', [])
        if api_chunks:
            console.print(f"  [green]🔄 API Routes from JS Chunks:[/green] {len(api_chunks)} found")
            for ac in api_chunks[:8]:
                console.print(f"    [dim]- {ac}[/dim]")
            if len(api_chunks) > 8:
                console.print(f"    [dim]... and {len(api_chunks)-8} more[/dim]")

        backend_proxy = nextjs_data.get('backend_proxy', [])
        if backend_proxy:
            console.print(f"  [yellow]🔁 Backend Proxy Patterns:[/yellow] {len(backend_proxy)}")
            for bp in backend_proxy:
                st = bp.get('status', bp.get('source', '?'))
                console.print(f"    [dim]{bp['path']}[/dim] ({st})")

    # ── Supabase RLS Testing ─────────────────────────
    supabase_rls = results.get('supabase_rls', {})
    if supabase_rls:
        console.print("\n[bold magenta]🛢️ Supabase RLS Analysis:[/bold magenta]")
        project = supabase_rls.get('supabase_project', {})
        if project:
            if project.get('project_ref'):
                console.print(f"  [cyan]Project Ref:[/cyan] {project['project_ref']}")
            if project.get('anon_key_preview'):
                console.print(f"  [yellow]Anon Key:[/yellow] {project['anon_key_preview']}")
            if project.get('service_role_warning'):
                console.print(f"  [bold red]⚠ {project['service_role_warning']}[/bold red]")

        open_tables = supabase_rls.get('rls_open_tables', [])
        if open_tables:
            rls_table = Table(title=f"[bold red]⚠ Open Supabase Tables ({len(open_tables)})[/bold red]",
                             show_header=True, header_style="bold red")
            rls_table.add_column("Table", style="cyan")
            rls_table.add_column("Status", style="yellow")
            rls_table.add_column("Preview", style="dim", width=50)
            for t in open_tables[:10]:
                rls_table.add_row(
                    t.get('table', '?'),
                    str(t.get('status', '?')),
                    str(t.get('preview', ''))[:48]
                )
            console.print(rls_table)

    # ── Supabase RPC Enumeration ─────────────────────
    supabase_rpc = results.get('supabase_rpc', {})
    exposed_rpcs = supabase_rpc.get('rpc_exposed', [])
    if exposed_rpcs:
        rpc_table = Table(title=f"[bold yellow]Supabase RPC Functions ({len(exposed_rpcs)})[/bold yellow]",
                         show_header=True, header_style="bold yellow")
        rpc_table.add_column("Function", style="cyan")
        rpc_table.add_column("Status", style="yellow")
        rpc_table.add_column("Needs Params", style="white")
        rpc_table.add_column("Response", style="dim", width=40)
        for f in exposed_rpcs[:15]:
            rpc_table.add_row(
                f.get('function', '?'),
                str(f.get('status', '?')),
                '[red]Yes[/red]' if f.get('needs_params') else '[green]No[/green]',
                str(f.get('response', f.get('error', '')))[:38]
            )
        console.print(rpc_table)

    # ── Supabase Storage Audit ───────────────────────
    supabase_storage = results.get('supabase_storage', {})
    public_buckets = supabase_storage.get('public_buckets', [])
    if public_buckets:
        storage_table = Table(title=f"[bold red]⚠ Public Supabase Storage Buckets ({len(public_buckets)})[/bold red]",
                             show_header=True, header_style="bold red")
        storage_table.add_column("Bucket ID", style="cyan")
        storage_table.add_column("Name", style="white")
        storage_table.add_column("Objects", style="yellow")
        storage_table.add_column("Public URLs", style="dim", width=40)
        for b in public_buckets[:10]:
            obj_count = b.get('object_count', 0)
            urls = b.get('public_urls', [])
            url_str = urls[0] if urls else '—'
            storage_table.add_row(
                b.get('id', '?'),
                b.get('name', '?'),
                str(obj_count),
                url_str[:38]
            )
        console.print(storage_table)

    common_buckets = supabase_storage.get('common_buckets', [])
    if common_buckets:
        console.print(f"  [yellow]→ {len(common_buckets)} additional accessible buckets via direct name guessing[/yellow]")
        for cb in common_buckets[:5]:
            console.print(f"    [dim]bucket/{cb['bucket']}: {cb.get('object_count', 0)} objects[/dim]")

    # ── Well-Known Discovery ─────────────────────────
    wk_data = results.get('wellknown', {})
    wk_files = wk_data.get('wellknown_files', [])
    if wk_files:
        console.print("\n[bold magenta]📄 Well-Known Files Discovery:[/bold magenta]")
        wk_table = Table(title=f"[bold]Well-Known Files ({len(wk_files)})[/bold]",
                        show_header=True, header_style="bold cyan")
        wk_table.add_column("Path", style="cyan")
        wk_table.add_column("Status", style="yellow")
        wk_table.add_column("Size", style="white")
        wk_table.add_column("Category", style="dim")
        for f in wk_files:
            wk_table.add_row(
                f.get('path', '?'),
                str(f.get('status', '?')),
                str(f.get('size', 0)),
                f.get('category', 'other'),
            )
        console.print(wk_table)

        llms = wk_data.get('llms_txt_found', [])
        if llms:
            console.print(f"  [bold yellow]📄 llms.txt FOUND — potential intelligence goldmine![/bold yellow]")
            for entry in llms:
                preview = entry.get('preview', '')
                if len(preview) > 300:
                    preview = preview[:300] + '...'
                console.print(f"  [dim]Content preview:[/dim]")
                console.print(f"  [white]{preview}[/white]")

        llms_analysis = wk_data.get('llms_analysis', {})
        if llms_analysis:
            for category, items in llms_analysis.items():
                if items:
                    console.print(f"  [cyan]{category.replace('_', ' ').title()}:[/cyan] {len(items)} items")
                    for item in items[:5]:
                        console.print(f"    [dim]- {item}[/dim]")

    # ── APK Analysis ─────────────────────────────────
    apk_data = results.get('apk', {})
    apk_refs = apk_data.get('apk_references', [])
    if apk_refs:
        console.print("\n[bold magenta]📱 APK/Mobile App References:[/bold magenta]")
        for ref in apk_refs:
            if ref.get('method') == 'direct_download':
                console.print(f"  [yellow]📦 APK:[/yellow] {ref['url']}")
            elif ref.get('method') == 'play_store':
                console.print(f"  [cyan]📱 Play Store:[/cyan] {ref.get('package', ref['url'])}")
            elif ref.get('method') == 'app_store':
                console.print(f"  [cyan]📱 App Store:[/cyan] {ref.get('bundle_id', ref['url'])}")

    apk_extracted = apk_data.get('apk_extracted', [])
    if apk_extracted:
        console.print(f"\n[bold yellow]🔍 APK Analysis Results ({len(apk_extracted)} APKs):[/bold yellow]")
        for ae in apk_extracted:
            endpoints = ae.get('extracted_endpoints', [])
            keys = ae.get('extracted_keys', [])
            urls = ae.get('extracted_urls', [])
            console.print(f"  [cyan]{ae['url']}[/cyan]")
            if endpoints:
                console.print(f"    [green]API Endpoints: {len(endpoints)}[/green]")
                for ep in endpoints[:5]:
                    console.print(f"      [dim]- {ep}[/dim]")
            if keys:
                console.print(f"    [red]Secrets: {len(keys)}[/red]")
                for k in keys[:5]:
                    console.print(f"      [yellow]{k.get('type', '?')}: {k.get('value', '?')}[/yellow]")
            if urls:
                console.print(f"    [dim]URLs: {len(urls)}[/dim]")

    # ── DNS Detritus ─────────────────────────────────
    dns_detritus = results.get('dns_detritus', {})
    total_detritus = dns_detritus.get('total_detritus', 0)
    if total_detritus:
        console.print(f"\n[bold yellow]🗑️ DNS Detritus Found ({total_detritus} records):[/bold yellow]")
        cloudflare_detritus = dns_detritus.get('cloudflare_detritus', [])
        if cloudflare_detritus:
            det_table = Table(title=f"[bold]Cloudflare DNS Detritus ({len(cloudflare_detritus)})[/bold]",
                             show_header=True, header_style="bold yellow")
            det_table.add_column("Subdomain", style="cyan")
            det_table.add_column("IP", style="white")
            det_table.add_column("Service", style="dim")
            det_table.add_column("Confidence", style="yellow")
            for d in cloudflare_detritus[:10]:
                det_table.add_row(
                    d.get('subdomain', '?'),
                    d.get('ip', '?'),
                    d.get('service', '?'),
                    d.get('confidence', '?'),
                )
            console.print(det_table)

        resolvable = dns_detritus.get('resolvable_legacy', [])
        if resolvable:
            console.print(f"  [yellow]→ {len(resolvable)} resolvable legacy DNS records[/yellow]")
            for r in resolvable[:5]:
                console.print(f"    [dim]{r['subdomain']} ({r['ip']})[/dim]")

    # ── Admin Subdomain Deep Scan ────────────────────
    admin_data = results.get('admin_scan', {})
    admin_subs = admin_data.get('admin_subdomains', [])
    if admin_subs:
        console.print(f"\n[bold magenta]🔐 Admin Subdomain Scan ({len(admin_subs)}):[/bold magenta]")
        admin_table = Table(title=f"[bold]Admin Subdomains[/bold]",
                           show_header=True, header_style="bold yellow")
        admin_table.add_column("Subdomain", style="cyan")
        admin_table.add_column("IP", style="white")
        admin_table.add_column("Status", style="yellow")
        admin_table.add_column("Type", style="dim")
        admin_table.add_column("Tech", style="green")
        for a in admin_subs[:15]:
            st = str(a.get('http_status', 'DNS'))
            st_str = f"[green]{st}[/]" if st in ['200', '301', '302'] else f"[yellow]{st}[/]"
            pg = a.get('page_type', '')
            tech = a.get('technologies', {})
            tech_str = ', '.join(tech.values()) if tech else ''
            admin_table.add_row(
                a.get('subdomain', '?'),
                a.get('ip', '?'),
                st_str,
                pg,
                tech_str,
            )
        console.print(admin_table)

        admin_paths = admin_data.get('admin_paths', [])
        if admin_paths:
            path_table = Table(title=f"[bold]Admin Paths ({len(admin_paths)})[/bold]",
                              show_header=True, header_style="bold yellow")
            path_table.add_column("Path", style="cyan")
            path_table.add_column("Status", style="yellow")
            path_table.add_column("Size", style="white")
            path_table.add_column("Redirect", style="dim", width=40)
            for p in admin_paths[:15]:
                redirect = p.get('redirect_to', '') or '—'
                path_table.add_row(
                    p.get('path', '?'),
                    str(p.get('status', '?')),
                    str(p.get('size', 0)),
                    redirect[:38],
                )
            console.print(path_table)

    # ── Atlassian Stack Recon ───────────────────────
    atlassian_data = results.get('atlassian', {})
    if atlassian_data and atlassian_data.get('detected'):
        console.print("\n[bold magenta]🔷 Atlassian Stack Recon:[/bold magenta]")
        jira = atlassian_data.get('jira', {})
        server_info = jira.get('/rest/api/2/serverInfo', {})
        if server_info.get('version'):
            console.print(f"  [cyan]🔄 Jira:[/cyan] {server_info['version']} ({server_info.get('deployment','?')})")
            if server_info.get('scm'):
                console.print(f"  [dim]Build:[/dim] {server_info.get('build')} | SCM: {server_info.get('scm')}")

        anon = atlassian_data.get('anonymous_access', {})
        if anon:
            console.print(f"  [bold red]⚠ Anonymous Access: {len(anon)} endpoint(s)[/bold red]")
            for ep, info in list(anon.items())[:5]:
                status = info.get('status', '?')
                data_preview = str(info.get('data', ''))[:80]
                console.print(f"    [dim]{ep}[/dim] ({status}) → {data_preview}")

        jira_login = jira.get('/login.jsp', {})
        if jira_login.get('meta_version'):
            console.print(f"  [dim]Meta version: {jira_login['meta_version']}[/dim]")

        dashboard = jira.get('/secure/Dashboard.jspa', {})
        if dashboard.get('leaked_project_id') or dashboard.get('confluence_urls'):
            console.print(f"  [yellow]🔑 Dashboard Leaks:[/yellow]")
            if dashboard.get('leaked_project_id'):
                console.print(f"    [dim]Project ID: {dashboard['leaked_project_id']}[/dim]")
            if dashboard.get('confluence_urls'):
                for cu in dashboard['confluence_urls'][:3]:
                    console.print(f"    [dim]Confluence: {cu}[/dim]")
            if dashboard.get('x_username'):
                console.print(f"    [dim]User: {dashboard['x_username']}[/dim]")

        azure = atlassian_data.get('azure_app_proxy', {})
        if azure.get('detected'):
            console.print(f"  [cyan]☁️ Azure App Proxy:[/cyan] Tenant {azure.get('tenant_id','')[:12]}...")
            console.print(f"    [dim]DC: {azure.get('data_center','?')} | Service: {azure.get('service_name','?')}[/dim]")

        saml = atlassian_data.get('saml_sso', {})
        if saml.get('saml_request_found'):
            console.print(f"  [yellow]🔐 SAML SSO:[/yellow] {saml.get('saml_endpoint','?')}")
            if saml.get('environment'):
                console.print(f"    [dim]Env: {saml['environment']} | Service: {saml.get('service','?')}[/dim]")

    # ── CORS Deep Scan ─────────────────────────────
    cors_data = results.get('cors', {})
    misconfigs = cors_data.get('misconfigurations', [])
    if misconfigs:
        console.print("\n[bold red]⚠ CORS Deep Scan Findings:[/bold red]")
        for m in misconfigs:
            severity = m.get('severity', 'LOW')
            color = "[bold red]" if severity == 'CRITICAL' else "[bold yellow]" if severity == 'HIGH' else "[yellow]"
            console.print(f"  {color}[{severity}] {m.get('message', '')[:120]}[/]")

    # ── OpenAPI Spec Discovery ─────────────────────
    oa_data = results.get('openapi', {})
    if oa_data.get('spec_found'):
        console.print(f"\n[bold cyan]📜 OpenAPI/Swagger Spec Analysis:[/bold cyan]")
        for spec in oa_data.get('specs', []):
            console.print(f"  [cyan]📄[/cyan] {spec.get('path', '?')} ({spec.get('size', 0)} bytes)")
            parsed = spec.get('parsed', {})
            if parsed:
                console.print(f"     [dim]Title: {parsed.get('title', '?')} | Version: {parsed.get('version', '?')}[/dim]")
                console.print(f"     [dim]Endpoints: {parsed.get('total_endpoints', 0)}[/dim]")
                unauth = parsed.get('unauthenticated_endpoints', [])
                if unauth:
                    console.print(f"     [bold yellow]⚠ {len(unauth)} endpoints without auth![/bold yellow]")
                    for ep in unauth[:5]:
                        console.print(f"       [dim]{ep['method']} {ep['path']}[/dim]")
                sensitive = parsed.get('sensitive_operations', [])
                if sensitive:
                    console.print(f"     [bold red]🚨 {len(sensitive)} sensitive operations:[/bold red]")
                    for sa in sensitive[:3]:
                        console.print(f"       [dim]{sa['method']} {sa['path']}[/dim]")

    # ── Server Leak Detection ──────────────────────
    sl_data = results.get('server_leaks', {})
    leaky = sl_data.get('leaky_headers', {})
    if leaky:
        console.print("\n[bold yellow]📡 Server Leak Analysis:[/bold yellow]")
        env = sl_data.get('environment_detected')
        if env:
            console.print(f"  [cyan]🏭 Environment:[/cyan] {env}")
        timing = sl_data.get('server_timing_analysis', {})
        internal_params = timing.get('internal_params', [])
        if internal_params:
            console.print(f"  [cyan]⏱ Server Timing Leaks:[/cyan]")
            for param in internal_params:
                label = param.get('internal_label', param.get('key', ''))
                value = param.get('value', '')
                console.print(f"    [dim]{label}: {value}[/dim]")
        versions = sl_data.get('version_disclosures', [])
        if versions:
            console.print(f"  [cyan]ℹ Version Disclosures:[/cyan]")
            for v in versions[:5]:
                console.print(f"    [dim]{v['header']}: {v['version']}[/dim]")
        regions = sl_data.get('internal_regions', [])
        if regions:
            console.print(f"  [cyan]🌍 Internal Regions:[/cyan] {', '.join(regions)}")
