#!/usr/bin/env python3
import sys
import os
import argparse
import json
import importlib
import requests
import urllib3
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align
from rich.markdown import Markdown

# Suppress SSL verification warnings (expected in recon)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


VERSION = "1.0.0"
console = Console()

BANNER = f"""[bold bright_green]
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗   ██████╗ ███████╗ ██████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝   ██╔══██╗██╔════╝██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗   ██████╔╝█████╗  ██║     
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║   ██╔══██╗██╔══╝  ██║     
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║   ██║  ██║███████╗╚██████╗
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝
[/bold bright_green]"""

INFO_PANEL = f"""[bold white]v{VERSION}[/bold white] [dim]│[/dim] [bold bright_green]Ihsan Alapsi[/bold bright_green] [dim]—[/dim] [dim]Software Eng. & Cyber Security Researcher[/dim]

[bold yellow]🛡️  Recon  ·  JS Analysis  ·  API Discovery  ·  DNS/SSL  ·  Vuln Scan[/bold yellow]"""

LINKS = """[link=https://github.com/ihsanalapsi]📦 GitHub[/link]  [dim]·[/dim]  [link=https://ihsanalapsi.dev]🌐 Web[/link]  [dim]·[/dim]  [link=https://www.linkedin.com/in/ihsan-alapsi/]💼 LinkedIn[/link]"""

MODULES_REGISTRY = {
    'basic': 'modules.recon.basic.BasicRecon',
    'subdomain': 'modules.recon.subdomain.SubdomainRecon',
    'js': 'modules.recon.js.JSRecon',
    'graphql': 'modules.recon.graphql.GraphQLRecon',
    'cloud': 'modules.recon.cloud.CloudRecon',
    'secrets': 'modules.recon.secrets.SecretsRecon',
    'vuln': 'modules.exploit.scanner.VulnScanner',
    'business': 'modules.exploit.business_logic.BusinessLogicScanner',
    'cookies': 'modules.recon.cookies.CookieRecon',
    'dns': 'modules.recon.dns.DNSRecon',
    'endpoints': 'modules.recon.endpoints.EndpointRecon',
    'payment': 'modules.recon.payment_gateway.PaymentGatewayRecon',
    'supabase_rls': 'modules.recon.supabase_rls.SupabaseRLSRecon',
    'supabase_rpc': 'modules.recon.supabase_rpc.SupabaseRPCRecon',
    'supabase_storage': 'modules.recon.supabase_storage.SupabaseStorageRecon',
    'wellknown': 'modules.recon.wellknown.WellKnownRecon',
    'apk': 'modules.recon.apk_analysis.APKRecon',
    'dns_detritus': 'modules.recon.dns_detritus.DNSDetritusRecon',
    'admin_scan': 'modules.recon.admin_scan.AdminScanRecon',
}

STACK_MODULES = {
    'Next.js': 'modules.stack.nextjs.NextJSRecon',
    'Laravel': 'modules.stack.laravel.LaravelRecon',
}

class NexusREC:
    def __init__(self, target, stealth=False, enabled_modules=None):
        self.target = target
        if not self.target.startswith("http"):
            self.target = f"https://{self.target}"
        self.domain = self.target.split("//")[-1].split("/")[0]
        self.stealth = stealth
        self.enabled_modules = enabled_modules
        self.results = {}
        self.modules = {}

    def _module_enabled(self, name):
        if self.enabled_modules is None:
            return True
        return name in self.enabled_modules

    def _load_module(self, module_path):
        try:
            parts = module_path.split('.')
            class_name = parts[-1]
            module_name = '.'.join(parts[:-1])
            mod = importlib.import_module(module_name)
            cls = getattr(mod, class_name)
            return cls(self.target)
        except Exception as e:
            console.print(f"[red]Failed to load {module_path}: {e}[/red]")
            return None

    def _run_module(self, name, module_obj, progress=None, task_id=None):
        try:
            if hasattr(module_obj, 'run_all'):
                result = module_obj.run_all()
            elif hasattr(module_obj, 'run'):
                result = module_obj.run()
            else:
                result = {}
            self.results[name] = getattr(module_obj, 'results', result)
        except Exception as e:
            self.results[name] = {'error': str(e)}
        if progress and task_id is not None:
            progress.update(task_id, advance=1)

    # ─────────────────────────────────────────────
    # SMART INTERACTIVE MODE HELPERS
    # ─────────────────────────────────────────────

    SCAN_PROFILES = {
        "1": {
            "name": "Quick Recon",
            "desc": "Headers, tech stack, WAF, security headers only (~30s)",
            "modules": ["basic"],
            "color": "green",
        },
        "2": {
            "name": "Web Surface Scan",
            "desc": "Basic + JS analysis, API endpoints, secrets, cookies (~2-3 min)",
            "modules": ["basic", "js", "secrets", "cookies", "endpoints"],
            "color": "cyan",
        },
        "3": {
            "name": "Infrastructure Scan",
            "desc": "Basic + subdomains, cloud buckets, DNS, SSL, ports (~3-5 min)",
            "modules": ["basic", "subdomain", "cloud", "dns"],
            "color": "yellow",
        },
        "4": {
            "name": "Vulnerability Scan",
            "desc": "Basic + vuln scanner, business logic, GraphQL (~4-6 min)",
            "modules": ["basic", "vuln", "business", "graphql"],
            "color": "red",
        },
        "5": {
            "name": "Full Scan (Smart Guided)",
            "desc": "All modules — adapts based on detected stack (~8-15 min)",
            "modules": None,
            "color": "magenta",
        },
    }

    def _interactive_menu(self):
        """Display scan profile menu and return selected modules list."""
        console.print(Panel(
            "[bold white]Select a Scan Profile[/bold white]\n"
            "[dim]The tool will auto-skip irrelevant modules based on detected tech.[/dim]",
            border_style="cyan",
            title="[bold cyan]⚙  SMART SCAN MODE[/bold cyan]"
        ))

        table = Table(show_header=True, header_style="bold white", border_style="dim")
        table.add_column("#", style="bold yellow", width=4)
        table.add_column("Profile", style="bold", width=26)
        table.add_column("Description", style="dim")
        table.add_column("ETA", style="cyan", width=12)

        etas = ["~30s", "~2-3 min", "~3-5 min", "~4-6 min", "~8-15 min"]
        for key, prof in self.SCAN_PROFILES.items():
            color = prof["color"]
            table.add_row(
                key,
                f"[{color}]{prof['name']}[/{color}]",
                prof["desc"],
                etas[int(key) - 1],
            )
        console.print(table)

        while True:
            choice = console.input("\n[bold yellow]  → Enter profile number (1-5): [/bold yellow]").strip()
            if choice in self.SCAN_PROFILES:
                selected = self.SCAN_PROFILES[choice]
                console.print(
                    f"\n  [bold green]✓ Selected:[/bold green] "
                    f"[bold {selected['color']}]{selected['name']}[/bold {selected['color']}]"
                )
                return selected["modules"]
            console.print("  [red]Invalid choice. Please enter a number from 1 to 5.[/red]")

    def _confirm_module(self, module_name: str, reason: str) -> bool:
        """Ask user whether to run an optional module (Smart Guided Mode)."""
        ans = console.input(
            f"  [dim]⤷[/dim] [yellow]{module_name}[/yellow]: {reason} "
            f"[dim]Run it? (y/n):[/dim] [bold yellow]"
        ).strip().lower()
        console.print("[/bold yellow]", end="")
        return ans in ("y", "yes", "")

    def _detect_js_from_html(self) -> bool:
        html = self.results.get("basic", {}).get("_html", "").lower()
        if not html:
            return True
        js_indicators = [
            '/static/js/', '/_next/static/', '/assets/index.',
            'webpack', 'bundle.js', 'chunk-', 'vendor.',
            'id="root"', 'id="__next"', 'id="app"',
            'react', 'vue', 'angular', 'svelte',
            'data-reactroot', '__NUXT__', '__SVELTEKIT__',
        ]
        return any(ind in html for ind in js_indicators)

    def _build_smart_plan(self) -> list[str]:
        plan = []
        stack   = self.results.get("detected_stack", [])
        tech    = self.results.get("basic", {}).get("technologies", {})
        waf     = self.results.get("basic", {}).get("waf", [])
        has_waf = bool(waf and "None Detected" not in waf and "Unknown" not in waf)
        tech_names = list(tech.keys())
        has_js_from_html = self._detect_js_from_html()

        plan.append("subdomain")
        plan.append("cloud")
        plan.append("dns")

        js_techs = ["React", "Next.js", "Vue.js", "Nuxt.js", "Angular",
                    "Svelte", "Webpack", "Vite", "JavaScript"]
        if any(t in tech_names for t in js_techs) or has_js_from_html:
            plan.append("js")
            plan.append("secrets")
        # JS analysis runs via should_run check in step_task

        if "GraphQL" in tech_names or "Apollo" in tech_names:
            plan.append("graphql")

        # ── Stack-specific modules ────────────────────
        if "Next.js" in stack:
            plan.append("nextjs")
        elif "Laravel" in stack:
            plan.append("laravel")

        # ── Vuln scanner ─────────────────────────────
        if has_waf:
            if self._ask_waf_bypass(waf):
                plan.append("vuln")
                plan.append("business")
        else:
            plan.append("vuln")
            plan.append("business")

        # ── Cookies & Endpoints always ────────────────
        plan.append("cookies")
        plan.append("endpoints")

        return plan

    def _ask_waf_bypass(self, waf: list) -> bool:
        waf_str = ", ".join(waf)
        console.print()
        console.print(Panel(
            "[bold yellow]⚠ WAF Detected:[/bold yellow] " + waf_str + "\n\n"
            "[dim]Vulnerability scan may trigger blocks/bans.[/dim]",
            border_style="yellow"
        ))
        ans = console.input(
            "  [bold white]┃  Continue with vuln scanning? (y/n): [/bold white]"
        ).strip().lower()
        return ans in ("y", "yes")

    # ─────────────────────────────────────────────
    # CORE RUN PIPELINE
    # ─────────────────────────────────────────────

    def run(self, auto: bool = False):
        from rich.progress import (
            Progress, SpinnerColumn, TextColumn,
            BarColumn, TaskProgressColumn, TimeElapsedColumn, MofNCompleteColumn
        )

        def _draw_header():
            """Clear screen, redraw BANNER + dynamic status line."""
            console.clear()
            console.print(Align.center(BANNER))
            status_text = (
                f"[bold bright_green]Nexus-REC v{VERSION}[/bold bright_green]  [dim]|[/dim]  "
                f"[bold yellow]Target: {self.domain if self.domain else '—'}[/bold yellow]  [dim]|[/dim]  "
                f"[bold white]Mode: {'AUTO' if auto else 'INTERACTIVE'}[/bold white]  [dim]|[/dim]  "
                f"[bold white]Stealth: {'ON' if self.stealth else 'OFF'}[/bold white]"
            )
            console.print(Align.center(Panel(Align.center(status_text), border_style="bright_green", width=76, padding=(1, 2))))
            console.print()

        # ── Phase 0: confirm target (interactive mode only) ──────────────
        if not auto:
            while True:
                _draw_header()
                console.print(Align.center(Panel(
                    Align.center(
                        f"  [bold white]Target:[/bold white]  [bold yellow]{self.domain}[/bold yellow]\n\n"
                        f"  [bold white]URL:[/bold white]     [dim]{self.target}[/dim]  "
                    ),
                    border_style="yellow",
                    title="[bold yellow]🎯 Confirm Target[/bold yellow]",
                    width=76,
                    padding=(1, 2)
                )))
                confirm = console.input(
                    "  Is this correct? "
                    "([bold green]y[/bold green] = yes  /  "
                    "[bold red]n[/bold red] = change): "
                ).strip().lower()

                if confirm in ("y", "yes", ""):
                    break
                elif confirm in ("n", "no"):
                    new_target = console.input(
                        "\n  [bold yellow]→ Enter new target: [/bold yellow]"
                    ).strip()
                    if not new_target:
                        console.print("\n  [red]No target entered. Keeping original.[/red]")
                        break
                    # Re-initialise with corrected target
                    self.target = (
                        f"https://{new_target}"
                        if not new_target.startswith("http") else new_target
                    )
                    self.domain = self.target.split("//")[-1].split("/")[0]
                    # Loop will clear & redraw with new target automatically
                else:
                    console.print("\n  [red]Please enter y or n.[/red]")

        # ── Phase 0b: choose scan profile ────────────────────────────────
        if not auto and self.enabled_modules is None:
            _draw_header()
            self.enabled_modules = self._interactive_menu()
            console.print()

        # ─────────────────────────────────────────
        # Build execution plan (module order list)
        # We run basic FIRST always, then decide.
        # ─────────────────────────────────────────
        ALL_STEPS = {
            "basic":           "Target Fingerprinting & Headers",
            "subdomain":       "Subdomain Enumeration",
            "cloud":           "Cloud & Bucket Detection",
            "js":              "JavaScript & API Extraction",
            "graphql":         "GraphQL Introspection",
            "secrets":         "Secrets & Exposed Files",
            "vuln":            "Vulnerability Scanner",
            "business":        "Business Logic Checks",
            "cookies":         "Cookie & Session Analysis",
            "dns":             "DNS, SSL & Port Analysis",
            "endpoints":       "Endpoint Discovery",
            "supabase_rls":    "Supabase RLS Policy Testing",
            "supabase_rpc":    "Supabase RPC Enumeration",
            "supabase_storage":"Supabase Storage Audit",
            "wellknown":       "Well-Known / llms.txt Discovery",
            "apk":             "APK Analysis",
            "dns_detritus":    "DNS Detritus Detection",
            "admin_scan":      "Admin Subdomain Deep Scan",
        }

        total_steps = len(ALL_STEPS)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:

            main_task = progress.add_task(
                "[bold white]Overall Progress[/bold white]",
                total=total_steps
            )

            completed = 0
            skipped_modules = []
            active_phase_num = 0

            def _overall_advance():
                nonlocal completed
                completed += 1
                total_steps = progress.tasks[main_task].total
                pct = min(99, int((completed / total_steps) * 100)) if total_steps > 0 else 99
                progress.update(
                    main_task,
                    advance=1,
                    description=f"[bold white]Overall Progress — {pct}%[/bold white]"
                )

            def _tick(label: str):
                _overall_advance()

            def _skip(key: str):
                nonlocal completed
                skipped_modules.append(key)
                total_steps = progress.tasks[main_task].total - 1
                pct = min(99, int((completed / total_steps) * 100)) if total_steps > 0 else 99
                progress.update(main_task, total=total_steps,
                    description=f"[bold white]Overall Progress — {pct}%[/bold white]")
                progress.update(main_task, advance=1)
                completed += 1

            def step_task(module_key: str) -> int:
                nonlocal active_phase_num
                active_phase_num += 1
                name = ALL_STEPS.get(module_key, "Task")
                # Explicit print for terminals that don't render Rich live updates
                progress.console.print(
                    f"  [bold cyan]▶ Phase {active_phase_num}:[/bold cyan] "
                    f"{name}..."
                )
                label = f"[cyan]  Phase {active_phase_num} — {name}[/cyan]"
                t = progress.add_task(label, total=2)
                progress.update(t, advance=1,
                    description=f"[cyan]  Phase {active_phase_num} — {name}...[/cyan]")
                progress.update(main_task,
                    description=f"[bold white]» {name}...[/bold white]")
                return t

            # ── STEP 1: Basic (ALWAYS) ───────────────────
            t = step_task('basic')
            basic_mod = self._load_module(MODULES_REGISTRY['basic'])
            if basic_mod:
                self._run_module('basic', basic_mod, progress, t)
            else:
                progress.update(t, advance=1)
            _tick("basic")

            # Collect detected info for smart decisions
            stack    = self.results.get('basic', {}).get('detected_stack', [])
            self.results['detected_stack'] = stack
            tech     = self.results.get('basic', {}).get('technologies', {})
            tech_names = list(tech.keys())
            waf      = self.results.get('basic', {}).get('waf', [])
            has_waf  = bool(waf and 'None Detected' not in waf and 'Unknown' not in waf)

            sec_block = self.results.get('basic', {}).get('security_block')
            if sec_block:
                progress.console.print(f"  [bold red]⚠ SECURITY BLOCK: {sec_block}[/bold red]")

            if tech:
                top = list(tech.keys())[:8]
                progress.console.print(
                    f"  [green]Detected {len(tech)} technologies: "
                    f"{', '.join(top)}{'...' if len(tech) > 8 else ''}[/green]"
                )
            if has_waf:
                progress.console.print(f"  [yellow]WAF: {', '.join(waf)}[/yellow]")
            if stack:
                progress.console.print(f"  [cyan]Stack: {', '.join(stack)}[/cyan]")

            # ── Payment Gateway Detection (passive, from basic HTML/CSP) ──
            basic_html = self.results.get('basic', {}).get('_html', '')
            basic_headers = self.results.get('basic', {}).get('headers', {})
            csp_header = basic_headers.get('Content-Security-Policy', basic_headers.get('content-security-policy', ''))
            if basic_html or csp_header:
                try:
                    from modules.recon.payment_gateway import PaymentGatewayRecon
                    pg = PaymentGatewayRecon(self.target)
                    pg_results = pg.run_all(html=basic_html, csp=csp_header, base_url=self.target)
                    if pg_results.get('csp_analysis') or pg_results.get('payment_keys'):
                        self.results['payment_gateway'] = pg_results
                        gateways = list(pg_results.get('csp_analysis', {}).keys())
                        if gateways:
                            progress.console.print(f"  [green]💳 Payment Gateways: {', '.join(gateways)}[/green]")
                        keys = pg_results.get('payment_keys', {})
                        if keys:
                            for provider, key_list in keys.items():
                                for k in key_list:
                                    if isinstance(k, dict):
                                        progress.console.print(f"  [yellow]🔑 {provider} key ({k.get('mode','?')}/{k.get('type','?')})[/yellow]")
                except Exception:
                    pass

            # ── Handle security block ─────────────────────────────
            if sec_block:
                progress.stop()
                console.print()
                console.print(Panel(
                    "[bold yellow]🔒 Security Block Active[/bold yellow]\n\n"
                    f"The target is protected by [bold]{sec_block}[/bold].\n"
                    "HTTP-based phases (JS, secrets, vuln) will likely fail.\n\n"
                    "[bold white]Options:[/bold white]\n"
                    "  [cyan]1[/cyan] Continue scan (results will be limited)\n"
                    "  [cyan]2[/cyan] Stop and try later\n\n"
                    "[dim]Tip: Wait 10-15 min or use a different IP[/dim]",
                    border_style="yellow", width=72
                ))
                choice = console.input(
                    "  [bold white]┃  Your choice (1/2): [/bold white]"
                ).strip()
                if choice == "2":
                    console.print("[red]Scan aborted by user.[/red]")
                    return
                console.print("  [dim]→ Continuing with limited results[/dim]")
                console.print()
                progress.start()

            # ── SMART plan override (Full Scan mode = modules is None) ──
            if not auto and self.enabled_modules is None and not sec_block:
                progress.stop()
                smart_plan = self._build_smart_plan()
                progress.start()
            elif auto and self.enabled_modules is None:
                smart_plan = None
            else:
                smart_plan = self.enabled_modules

            def should_run(key: str) -> bool:
                if smart_plan is None:
                    return True
                return key in smart_plan

            # ── STEP 2: Subdomains ───────────────────────
            sub_mod = None
            if should_run('subdomain'):
                t = step_task('subdomain')
                sub_mod = self._load_module(MODULES_REGISTRY['subdomain'])
                if sub_mod:
                    sub_mod.domain = self.domain
                    self._run_module('subdomain', sub_mod, progress, t)
                    # Auto-run backend IP discovery on resolved subdomain IPs
                    sub_results = self.results.get('subdomain', {})
                    resolved_subs = sub_results.get('subdomains', [])
                    bkapi_subs = [s for s in resolved_subs
                                  if any(kw in s.get('subdomain', '').lower()
                                         for kw in ['bkapi', 'backend', 'api-server', 'api-backend', 'internal-api'])
                                  and s.get('ip')]
                    if bkapi_subs:
                        progress.console.print(f"  [green]→ Found {len(bkapi_subs)} backend subdomain(s), probing IP redirects...[/green]")
                        ip_discoveries = []
                        for bs in bkapi_subs[:5]:
                            disc = sub_mod.discover_backend_from_ip(bs['ip'])
                            if disc.get('redirect_found'):
                                ip_discoveries.append(disc)
                                progress.console.print(f"    [yellow]⚡ {bs['ip']} → {disc.get('backend_domain')}[/yellow]")
                        if ip_discoveries:
                            self.results['backend_ip_discovery'] = ip_discoveries
                            self.results['subdomain'] = getattr(sub_mod, 'results', self.results.get('subdomain', {}))
                else:
                    progress.update(t, advance=1)
                _tick("subdomain")
            else:
                _skip("subdomain")

            # ── STEP 3: Cloud ────────────────────────────
            if should_run('cloud'):
                t = step_task('cloud')
                cloud_mod = self._load_module(MODULES_REGISTRY['cloud'])
                if cloud_mod:
                    cloud_mod.domain = self.domain
                    self._run_module('cloud', cloud_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("cloud")
            else:
                _skip("cloud")

            # ── STEP 4: JS Analysis ──────────────────────
            js_mod = None
            if should_run('js'):
                t = step_task('js')
                js_mod = self._load_module(MODULES_REGISTRY['js'])
                if js_mod:
                    self._run_module('js', js_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("js")
                # Feed JS APIs back to subdomain module
                js_apis = self.results.get('js', {}).get('extracted_apis', [])
                if js_apis and sub_mod is not None:
                    sub_mod.extract_from_js_apis(js_apis)
                    sub_mod.discover_related_domains(js_apis)
                    sub_mod.discover_backends_from_js(js_apis)
                    self.results['subdomain'] = getattr(sub_mod, 'results', self.results.get('subdomain', {}))
                # Auto-enable graphql module if JS found graphql endpoints
                if js_apis and any('graphql' in a.lower() for a in js_apis):
                    if smart_plan is not None and 'graphql' not in smart_plan:
                        smart_plan.append('graphql')
                        progress.console.print("  [green]→ GraphQL endpoints detected in JS, enabling graphql module[/green]")
                        total_phases = progress.tasks[main_task].total
                        progress.update(main_task, total=total_phases + 1)
            else:
                _skip("js")

            # ── STEP 5: GraphQL ──────────────────────────
            if should_run('graphql'):
                t = step_task('graphql')
                gql_mod = self._load_module(MODULES_REGISTRY['graphql'])
                if gql_mod:
                    self._run_module('graphql', gql_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("graphql")
            else:
                _skip("graphql")

            # ── STEP 6: Secrets ──────────────────────────
            if should_run('secrets'):
                t = step_task('secrets')
                sec_mod = self._load_module(MODULES_REGISTRY['secrets'])
                if sec_mod:
                    self._run_module('secrets', sec_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("secrets")
            else:
                _skip("secrets")

            # Stack-specific module (Next.js / Laravel)
            det_stack = self.results.get('detected_stack', [])
            if "Next.js" in det_stack and should_run('nextjs'):
                nextjs_mod = self._load_module(STACK_MODULES['Next.js'])
                if nextjs_mod:
                    basic_html    = self.results.get('basic', {}).get('_html', '')
                    raw_headers   = self.results.get('basic', {}).get('headers', {}).get('_raw_headers', {})
                    if basic_html:
                        nextjs_mod.set_initial_response(basic_html, raw_headers)
                    t_nx = step_task('nextjs')
                    self._run_module('nextjs', nextjs_mod, progress, t_nx)
            elif "Laravel" in det_stack and should_run('laravel'):
                laravel_mod = self._load_module(STACK_MODULES['Laravel'])
                if laravel_mod:
                    t_lv = step_task('laravel')
                    self._run_module('laravel', laravel_mod, progress, t_lv)

            # ── STEP 7: Vuln Scanner ─────────────────────
            if should_run('vuln'):
                t = step_task('vuln')
                vuln_mod = self._load_module(MODULES_REGISTRY['vuln'])
                if vuln_mod:
                    self._run_module('vulnerabilities', vuln_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("vuln")
            else:
                _skip("vuln")

            # ── STEP 8: Business Logic ───────────────────
            if should_run('business'):
                t = step_task('business')
                biz_mod = self._load_module(MODULES_REGISTRY['business'])
                if biz_mod:
                    self._run_module('business_logic', biz_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("business")
            else:
                _skip("business")

            # ── STEP 9: Cookies ──────────────────────────
            if should_run('cookies'):
                t = step_task('cookies')
                cookie_mod = self._load_module(MODULES_REGISTRY['cookies'])
                if cookie_mod:
                    self._run_module('cookies', cookie_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("cookies")
            else:
                _skip("cookies")

            # ── STEP 10: DNS ─────────────────────────────
            if should_run('dns'):
                t = step_task('dns')
                dns_mod = self._load_module(MODULES_REGISTRY['dns'])
                if dns_mod:
                    self._run_module('dns', dns_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("dns")
            else:
                _skip("dns")

            # ── STEP 11: Endpoints ───────────────────────
            if should_run('endpoints'):
                t = step_task('endpoints')
                ep_mod = self._load_module(MODULES_REGISTRY['endpoints'])
                if ep_mod:
                    self._run_module('endpoints', ep_mod, progress, t)
                else:
                    progress.update(t, advance=1)
                _tick("endpoints")
            else:
                _skip("endpoints")

            # ── STEP 12: Supabase RLS Testing ──────────────
            if should_run('supabase_rls'):
                t = step_task('supabase_rls')
                supabase_mod = self._load_module(MODULES_REGISTRY['supabase_rls'])
                if supabase_mod:
                    self._run_module('supabase_rls', supabase_mod, progress, t)
                    open_tables = self.results.get('supabase_rls', {}).get('rls_open_tables', [])
                    if open_tables:
                        progress.console.print(f"  [bold red]⚠ {len(open_tables)} Supabase tables accessible with anon_key![/bold red]")
                else:
                    progress.update(t, advance=1)
                _tick("supabase_rls")
            else:
                _skip("supabase_rls")

            # ── STEP 13: Supabase RPC Enumeration ──────────
            if should_run('supabase_rpc'):
                t = step_task('supabase_rpc')
                rpc_mod = self._load_module(MODULES_REGISTRY['supabase_rpc'])
                if rpc_mod:
                    self._run_module('supabase_rpc', rpc_mod, progress, t)
                    exposed_rpcs = self.results.get('supabase_rpc', {}).get('rpc_exposed', [])
                    if exposed_rpcs:
                        progress.console.print(f"  [bold yellow]⚡ {len(exposed_rpcs)} Supabase RPC functions discovered[/bold yellow]")
                else:
                    progress.update(t, advance=1)
                _tick("supabase_rpc")
            else:
                _skip("supabase_rpc")

            # ── STEP 14: Supabase Storage Audit ────────────
            if should_run('supabase_storage'):
                t = step_task('supabase_storage')
                storage_mod = self._load_module(MODULES_REGISTRY['supabase_storage'])
                if storage_mod:
                    self._run_module('supabase_storage', storage_mod, progress, t)
                    public_buckets = self.results.get('supabase_storage', {}).get('public_buckets', [])
                    if public_buckets:
                        progress.console.print(f"  [bold red]⚠ {len(public_buckets)} public Supabase storage buckets found![/bold red]")
                else:
                    progress.update(t, advance=1)
                _tick("supabase_storage")
            else:
                _skip("supabase_storage")

            # ── STEP 15: Well-Known Discovery ──────────────
            if should_run('wellknown'):
                t = step_task('wellknown')
                wk_mod = self._load_module(MODULES_REGISTRY['wellknown'])
                if wk_mod:
                    self._run_module('wellknown', wk_mod, progress, t)
                    llms = self.results.get('wellknown', {}).get('llms_txt_found', [])
                    if llms:
                        progress.console.print(f"  [bold yellow]📄 llms.txt found! Potential intelligence source[/bold yellow]")
                else:
                    progress.update(t, advance=1)
                _tick("wellknown")
            else:
                _skip("wellknown")

            # ── STEP 16: APK Analysis ──────────────────────
            if should_run('apk'):
                t = step_task('apk')
                apk_mod = self._load_module(MODULES_REGISTRY['apk'])
                if apk_mod:
                    self._run_module('apk', apk_mod, progress, t)
                    apk_refs = self.results.get('apk', {}).get('apk_references', [])
                    if apk_refs:
                        progress.console.print(f"  [green]📱 {len(apk_refs)} APK/App references found[/green]")
                    apk_keys = self.results.get('apk', {}).get('apk_secrets', [])
                    if apk_keys:
                        progress.console.print(f"  [bold yellow]🔑 {len(apk_keys)} potential secrets extracted from APK[/bold yellow]")
                else:
                    progress.update(t, advance=1)
                _tick("apk")
            else:
                _skip("apk")

            # ── STEP 17: DNS Detritus Detection ───────────
            if should_run('dns_detritus'):
                t = step_task('dns_detritus')
                detritus_mod = self._load_module(MODULES_REGISTRY['dns_detritus'])
                if detritus_mod:
                    self._run_module('dns_detritus', detritus_mod, progress, t)
                    total = self.results.get('dns_detritus', {}).get('total_detritus', 0)
                    if total:
                        progress.console.print(f"  [bold yellow]🗑️ {total} DNS detritus records found[/bold yellow]")
                else:
                    progress.update(t, advance=1)
                _tick("dns_detritus")
            else:
                _skip("dns_detritus")

            # ── STEP 18: Admin Subdomain Deep Scan ────────
            if should_run('admin_scan'):
                t = step_task('admin_scan')
                admin_mod = self._load_module(MODULES_REGISTRY['admin_scan'])
                if admin_mod:
                    self._run_module('admin_scan', admin_mod, progress, t)
                    admin_subs = self.results.get('admin_scan', {}).get('admin_subdomains', [])
                    if admin_subs:
                        progress.console.print(f"  [bold yellow]🔐 {len(admin_subs)} admin subdomains discovered[/bold yellow]")
                    accessible = self.results.get('admin_scan', {}).get('accessible_admin', [])
                    if accessible:
                        progress.console.print(f"  [bold red]⚠ {len(accessible)} admin subdomains potentially accessible![/bold red]")
                else:
                    progress.update(t, advance=1)
                _tick("admin_scan")
            else:
                _skip("admin_scan")

            # ── STEP 19: Backend URL scan (from JS analysis) ──
            backend_urls = self.results.get('subdomain', {}).get('backend_discovered', [])
            real_backends = [b for b in backend_urls
                             if self.domain not in b.get('url', '')
                             and 'google' not in b.get('url', '')
                             and 'w3.org' not in b.get('url', '')
                             and 'apple.com' not in b.get('url', '')
                             and 'cloudflare' not in b.get('url', '')
                             and 'react.dev' not in b.get('url', '')]
            if real_backends and should_run('endpoints'):
                progress.console.print(f"  [bold cyan]⚡ Scanning {len(real_backends)} backend server(s) for APIs...[/bold cyan]")
                self.results['backend_scan'] = {}
                for b in real_backends[:3]:
                    b_url = b.get('url', '')
                    progress.console.print(f"    [dim]→ {b_url}[/dim]")
                    try:
                        r = requests.get(b_url, timeout=8,
                            headers={'User-Agent': 'Mozilla/5.0'})
                        be_result = {
                            'url': b_url,
                            'status': r.status_code,
                            'size': len(r.content),
                            'server': r.headers.get('Server', ''),
                            'content_type': r.headers.get('Content-Type', ''),
                        }
                        if 'text/html' not in be_result.get('content_type', ''):
                            be_result['preview'] = r.text[:300]
                        # Quick API probe
                        for api_path in ['/api/', '/health', '/status', '/graphql', '/docs']:
                            try:
                                ar = requests.get(f"{b_url.rstrip('/')}{api_path}", timeout=5,
                                    headers={'User-Agent': 'Mozilla/5.0'})
                                if ar.status_code not in [404, 405]:
                                    be_result.setdefault('api_endpoints', []).append({
                                        'path': api_path,
                                        'status': ar.status_code,
                                        'size': len(ar.content),
                                    })
                            except:
                                pass
                        self.results['backend_scan'][b_url] = be_result
                    except Exception as e:
                        self.results['backend_scan'][b_url] = {'url': b_url, 'error': str(e)}

            # Final summary of skipped modules
            if skipped_modules:
                progress.console.print(f"  [dim]→ Skipped ({len(skipped_modules)} modules): {', '.join(skipped_modules)}[/dim]")

            # Finalize progress bar to 100%
            progress.update(main_task, completed=progress.tasks[main_task].total,
                            description="[bold green]Overall Progress — 100%  ✓ Done[/bold green]")


        console.print()
        self.display_summary()
        self.save_results()

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

    def _group_technologies(self):
        tech_details = self.results.get('basic', {}).get('tech_details', {})
        groups = {}
        for tech_name, info in tech_details.items():
            override = self.TECH_OVERRIDES.get(tech_name)
            if override:
                groups.setdefault(override, []).append(tech_name)
                continue
            cats = info.get('categories', [])
            matched = False
            for cat in cats:
                for key, gname in self.CATEGORY_GROUPS.items():
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

    def display_summary(self):
        console.print("\n")
        stack_str = ", ".join(self.results.get('detected_stack', ['Unknown']))
        waf = self.results.get('basic', {}).get('waf', [])
        waf_str = ", ".join(waf) if waf and 'None Detected' not in waf else "None"
        tech = self.results.get('basic', {}).get('technologies', {})
        tech_count = len(tech)
        console.print(Panel(
            f"[bold cyan]Target:[/bold cyan] [bold white]{self.domain}[/bold white]\n"
            f"[bold cyan]Stack:[/bold cyan] [bold white]{stack_str}[/bold white]\n"
            f"[bold cyan]WAF:[/bold cyan] [bold white]{waf_str}[/bold white]\n"
            f"[bold cyan]Technologies:[/bold cyan] [bold white]{tech_count} detected[/bold white]",
            border_style="blue", title="[bold]Target Summary[/bold]"
        ))

        groups = self._group_technologies()
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
        headers = self.results.get('basic', {}).get('headers', {})
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

        sub_data = self.results.get('subdomain', {})
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

        cloud_data = self.results.get('cloud', {})
        buckets = cloud_data.get('s3_buckets', [])
        if buckets:
            console.print(f"[bold red]⚠ Open S3 Buckets: {len(buckets)}[/bold red]")
            for b in buckets:
                mark = "[red]PUBLIC[/red]" if b.get('public') else "[yellow]RESTRICTED[/yellow]"
                console.print(f"  {mark} {b['url']}")
        cf = cloud_data.get('cloudfront', {})
        if cf.get('detected'):
            console.print(f"  [yellow]CloudFront Distribution Detected[/yellow]")

        sub_data = self.results.get('subdomain', {})
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

        js_data = self.results.get('js', {})
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

        gql_data = self.results.get('graphql', {})
        introspection = gql_data.get('introspection', {})
        for url, status in introspection.items():
            if status.get('introspection_enabled'):
                console.print(f"[bold red]⚠ GraphQL Introspection ENABLED at:[/bold red] {url}")
                if status.get('sensitive_count', 0) > 0:
                    console.print(f"  [bold red]Sensitive types exposed: {status['sensitive_count']}[/bold red]")

        vuln_data = self.results.get('vulnerabilities', {})
        total_vulns = sum(len(v) for v in vuln_data.values() if isinstance(v, list))
        homepage_len = self.results.get('basic', {}).get('content_length', 0)

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
        real_vulns = {k: v for k, v in vuln_data.items() if isinstance(v, list) and v}

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

                for v in vlist[:10]:
                    ep = v.get('endpoint', v.get('path', ''))
                    st = v.get('status', '?')
                    sz = v.get('size', '?')
                    ct = v.get('content_type', v.get('type', v.get('mode', '')))
                    preview = v.get('preview', '')[:100].lower()

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
                for v in vlist:
                    if v.get('size') == homepage_len:
                        total_spa += 1
            if total_spa > 0:
                console.print(f"  [dim]ℹ {total_spa}/{total_vulns} findings are SPA catchall pages "
                              f"(same content as homepage), likely false positives[/dim]")

        # Restore http_methods for completeness
        vuln_data['http_methods'] = method_findings

        secrets_data = self.results.get('secrets', {})
        exposed = secrets_data.get('exposed_files', [])
        if exposed:
            console.print(f"\n[bold red]Exposed Sensitive Files: {len(exposed)}[/bold red]")
            for f in exposed[:5]:
                console.print(f"  [red]{f['path']}[/red] -> Status: {f['status']} ({f['size']} bytes)")
        blocked_paths = secrets_data.get('blocked_paths', [])
        if blocked_paths:
            console.print(f"\n[dim]🚫 Blocked Paths ({len(blocked_paths)}): 403 — edge/WAF protection active[/dim]")

        # Internal machine names (from basic or secrets)
        basic_data = self.results.get('basic', {})
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
        cookie_data = self.results.get('cookies', {})
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
        dns_data = self.results.get('dns', {})
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
        ep_data = self.results.get('endpoints', {})
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
        backend_scan = self.results.get('backend_scan', {})
        if backend_scan:
            btable = Table(title=f"[bold cyan]⚡ Backend API Scan ({len(backend_scan)})[/bold cyan]",
                          show_header=True, header_style="bold cyan")
            btable.add_column("Backend URL", style="cyan", width=45)
            btable.add_column("Status", style="yellow", width=8)
            btable.add_column("Server", style="white", width=15)
            btable.add_column("Type", style="dim", width=20)
            btable.add_column("APIs Found", style="green", width=15)
            for b_url, b_info in backend_scan.items():
                st = b_info.get('status', b_info.get('error', '?'))
                sv = b_info.get('server', '')
                ct = b_info.get('content_type', '')[:20]
                apis = b_info.get('api_endpoints', [])
                api_str = ', '.join(f"{a['path']}({a['status']})" for a in apis) if apis else '—'
                btable.add_row(b_url, str(st), sv, ct, api_str)
            console.print(btable)

        # Backend IP Discovery (from subdomain IP redirect probing)
        ip_disc = self.results.get('backend_ip_discovery', [])
        if ip_disc:
            console.print(f"\n[bold yellow]🔍 Backend IP Discovery ({len(ip_disc)}):[/bold yellow]")
            for d in ip_disc:
                console.print(f"  [cyan]{d['ip']}[/cyan] → [green]{d.get('redirect_url', 'N/A')}[/green]")
                if d.get('backend_domain'):
                    console.print(f"    [dim]Domain: {d['backend_domain']}[/dim]")

        # ── Payment Gateway Insights ──
        pg_data = self.results.get('payment_gateway', {})
        if pg_data:
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
        laravel_data = self.results.get('laravel', {})
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

            # Routes & Inertia
            if laravel_data.get('routes_exposed'):
                console.print(f"  [green]🛣️ Routes:[/green] {len(laravel_data.get('routes', []))} endpoints exposed via window.routes")
            
            inertia = laravel_data.get('inertia', {})
            if inertia.get('detected'):
                ver = inertia.get('version', 'Unknown')
                console.print(f"  [cyan]⚛️ Inertia.js:[/cyan] Detected (Version: {ver})")

        nextjs_data = self.results.get('nextjs', {})
        if nextjs_data:
            console.print("\n[bold magenta]💎 Next.js Insights:[/bold magenta]")
            if nextjs_data.get('version'):
                console.print(f"  [cyan]🚀 Version:[/cyan] {nextjs_data['version']}")
            if nextjs_data.get('build_id'):
                console.print(f"  [dim]Build ID: {nextjs_data['build_id']}[/dim]")
            
            if nextjs_data.get('middleware_bypass'):
                details = nextjs_data.get('middleware_details', {})
                console.print(f"  [bold red]⚠ CRITICAL: Middleware Bypass Detected![/bold red]")
                console.print(f"    [dim]Path: {details.get('path')} | Payload: {details.get('payload')}[/dim]")
            
            leaks = nextjs_data.get('leaks', [])
            if leaks:
                for leak in leaks:
                    console.print(f"  [yellow]⚠ Leak:[/yellow] {leak}")

        # ── Supabase RLS Testing ─────────────────────────
        supabase_rls = self.results.get('supabase_rls', {})
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
        supabase_rpc = self.results.get('supabase_rpc', {})
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
        supabase_storage = self.results.get('supabase_storage', {})
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
        wk_data = self.results.get('wellknown', {})
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
        apk_data = self.results.get('apk', {})
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
                        console_print = console.print
                        console_print(f"      [yellow]{k.get('type', '?')}: {k.get('value', '?')}[/yellow]")
                if urls:
                    console.print(f"    [dim]URLs: {len(urls)}[/dim]")

        # ── DNS Detritus ─────────────────────────────────
        dns_detritus = self.results.get('dns_detritus', {})
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
                    console_print(f"    [dim]{r['subdomain']} ({r['ip']})[/dim]")

        # ── Admin Subdomain Deep Scan ────────────────────
        admin_data = self.results.get('admin_scan', {})
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

    def save_results(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(script_dir, 'results')
        os.makedirs(output_dir, exist_ok=True)
        sanitized_domain = self.domain.replace(':', '_').replace('/', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}-{sanitized_domain}.json"
        output_file = os.path.join(output_dir, filename)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str, ensure_ascii=False)
        console.print(f"\n[bold green]✓ Report: [/bold green]{output_file}")
        return output_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Nexus-REC v1.0 — Modular Reconnaissance & Vulnerability Assessment Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com --stealth
  %(prog)s example.com --modules basic,js,vuln

Author: Ihsan Alapsi — https://github.com/ihsanalapsi/Nexus-REC
        """
    )
    # target is optional — if missing we prompt interactively
    parser.add_argument(
        "target", nargs="?", default=None,
        help="Target domain or URL (e.g. example.com or https://example.com). "
             "If omitted, the tool will ask you interactively."
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Enable stealth mode (longer delays, fewer concurrent requests)"
    )
    parser.add_argument(
        "--modules", type=str, default="all",
        help="Comma-separated list of modules to run (bypasses profile selector). "
             "Use 'all' to run everything without prompts."
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Non-interactive automation mode: skip all menus and prompts, "
             "run full scan intelligently. Ideal for ihsanalapsi_dev.py or CI pipelines."
    )
    args = parser.parse_args()

    # ── If no target was given, show welcome and ask interactively ──
    if not args.target:
        from rich.table import Table
        
        # Internal layout grid with separator
        grid = Table.grid(expand=True)
        grid.add_column(ratio=10) # Left
        grid.add_column(ratio=1, justify="center") # Separator
        grid.add_column(ratio=10) # Right

        info_side = (
            "[bold bright_green]DEVELOPER[/bold bright_green]\n"
            "[white]Ihsan Alapsi[/white]\n"
            "[dim]Software Eng. & Cyber Security[/dim]\n\n"
            "[bold yellow]MODULES[/bold yellow]\n"
            "[dim]Recon · JS · API · DNS · Vuln[/dim]"
        )

        separator = "\n[dim]│[/dim]\n[dim]│[/dim]\n[dim]│[/dim]\n[dim]│[/dim]\n[dim]│[/dim]"

        usage_side = (
            "[bold bright_green]QUICK START[/bold bright_green]\n"
            "[dim]python3 nexus_rec.py <target>[/dim]\n"
            "[dim]Mode: --auto (Interactive: off)[/dim]\n\n"
            "[bold white]COMMAND FLAGS[/bold white]\n"
            "[dim]--auto | --stealth | --modules[/dim]"
        )

        grid.add_row(info_side, separator, usage_side)

        main_panel = Panel(
            grid,
            title=f"[bold white] NEXUS-REC v{VERSION} [/bold white]",
            border_style="bright_green",
            padding=(1, 4),
            width=90
        )

        console.clear()
        console.print(Align.center(BANNER))
        console.print(Align.center(LINKS))
        console.print()
        console.print(Align.center(main_panel))
        
        try:
            target_input = console.input(
                "\n  [bold bright_green]→[/bold bright_green] [bold white]Enter target domain or URL:[/bold white] "
            ).strip()
        except KeyboardInterrupt:
            console.print("\n\n[bold red]⛔ Cancelled.[/bold red]")
            sys.exit(0)

        if not target_input:
            console.print("[red]  No target provided. Exiting.[/red]")
            sys.exit(1)

        args.target = target_input
        console.print()

    # ── Resolve module list ──
    if args.modules and args.modules != 'all':
        enabled = set(m.strip() for m in args.modules.split(','))
    else:
        enabled = None

    try:
        recon = NexusREC(args.target, stealth=args.stealth, enabled_modules=enabled)
        recon.run(auto=args.auto)
    except KeyboardInterrupt:
        console.print("\n\n[bold red]⛔ Scan interrupted by user.[/bold red]")
        sys.exit(0)


