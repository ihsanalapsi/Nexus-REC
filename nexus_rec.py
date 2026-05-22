#!/usr/bin/env python3
import urllib3
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from modules.core.config import (
    MODULES_REGISTRY,
    SCAN_MODES,
    STACK_MODULES,
    VERSION,
)
from modules.core.cli import run_cli, validate_target
from modules.core.module_loader import load_module
from modules.core.pipeline import (
    BASELINE_STEPS,
    HTTP_HEAVY_STEPS,
    STEP_BY_KEY,
    STEP_TITLES,
    planned_total,
)
from modules.core.reporter import save_scan_results
from modules.core.summary import display_summary

# Suppress SSL verification warnings (expected in recon)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


console = Console()

BANNER = f"""[bold bright_green]
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗   ██████╗ ███████╗ ██████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝   ██╔══██╗██╔════╝██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗   ██████╔╝█████╗  ██║     
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║   ██╔══██╗██╔══╝  ██║     
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║   ██║  ██║███████╗╚██████╗
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝
[/bold bright_green]"""

LINKS = """[link=https://github.com/ihsanalapsi]📦 GitHub[/link]  [dim]·[/dim]  [link=https://ihsanalapsi.dev]🌐 Web[/link]  [dim]·[/dim]  [link=https://www.linkedin.com/in/ihsan-alapsi/]💼 LinkedIn[/link]"""

class NexusREC:
    def __init__(self, target, stealth=False, enabled_modules=None,
                 scan_mode="safe", redact_report=False):
        self.target = target
        if not self.target.startswith("http"):
            self.target = f"https://{self.target}"
        self.domain = self.target.split("//")[-1].split("/")[0]
        self.stealth = stealth
        self.enabled_modules = enabled_modules
        self.scan_mode = scan_mode if scan_mode in SCAN_MODES else "safe"
        self.redact_report = redact_report
        self.results = {}
        self.modules = {}

    def _module_enabled(self, name):
        if self.enabled_modules is None:
            return True
        return name in self.enabled_modules

    def _load_module(self, module_path):
        return load_module(
            module_path,
            self.target,
            scan_mode=self.scan_mode,
            stealth=self.stealth,
            console=console,
        )

    def _run_module(self, name, module_obj, progress=None, task_id=None):
        try:
            if hasattr(module_obj, 'run_all'):
                result = module_obj.run_all()
            elif hasattr(module_obj, 'run'):
                result = module_obj.run()
            else:
                result = {}
            self.results[name] = getattr(module_obj, 'results', result)
            completed = self.results.setdefault('scan_metadata', {}).setdefault('completed_result_sections', [])
            if name not in completed:
                completed.append(name)
        except Exception as e:
            self.results[name] = {'error': str(e)}
        if progress and task_id is not None:
            progress.update(task_id, advance=1)

    def _input(self, prompt, default=None):
        try:
            return console.input(prompt).strip()
        except KeyboardInterrupt:
            console.print("\n\n[bold red]⛔ Cancelled.[/bold red]")
            raise
        except EOFError:
            if default is not None:
                return default
            console.print("\n[red]Input stream closed. Exiting safely.[/red]")
            raise KeyboardInterrupt

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
            choice = self._input("\n[bold yellow]  → Enter profile number (1-5): [/bold yellow]", default="5")
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
        ans = self._input(
            f"  [dim]⤷[/dim] [yellow]{module_name}[/yellow]: {reason} "
            f"[dim]Run it? (y/n):[/dim] [bold yellow]"
        , default="").lower()
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

    def _build_smart_plan(self, allow_prompts: bool = True) -> list[str]:
        plan = []
        reasons = {}
        skip_reasons = {}
        stack   = self.results.get("detected_stack", [])
        tech    = self.results.get("basic", {}).get("technologies", {})
        waf     = self.results.get("basic", {}).get("waf", [])
        has_waf = bool(waf and "None Detected" not in waf and "Unknown" not in waf)
        tech_names = list(tech.keys())
        has_js_from_html = self._detect_js_from_html()
        basic = self.results.get("basic", {})
        security_block = basic.get("security_block")
        headers = basic.get("headers", {})
        csp_header = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        html = basic.get("_html", "")

        def add(module_key: str, reason: str):
            if module_key not in plan:
                plan.append(module_key)
            reasons[module_key] = reason

        def skip(module_key: str, reason: str):
            if module_key not in plan:
                skip_reasons[module_key] = reason

        def detected(*names: str) -> bool:
            lowered = {str(t).lower() for t in tech_names + list(stack)}
            return any(name.lower() in lowered for name in names)

        for key, step in STEP_BY_KEY.items():
            if key != "basic" and key in BASELINE_STEPS:
                add(key, step.reason)

        if security_block:
            block_reason = f"Security challenge detected ({security_block}); HTTP-heavy module likely blocked."
            for key in sorted(HTTP_HEAVY_STEPS):
                skip(key, block_reason)
            self._record_smart_plan(plan, reasons, skip_reasons)
            return plan

        js_techs = ["React", "Next.js", "Vue.js", "Nuxt.js", "Angular",
                    "Svelte", "Webpack", "Vite", "JavaScript"]
        if any(t in tech_names for t in js_techs) or has_js_from_html:
            add("js", STEP_BY_KEY["js"].reason)
            add("secrets", STEP_BY_KEY["secrets"].reason)
        else:
            skip("js", STEP_BY_KEY["js"].skip_reason)
            skip("secrets", STEP_BY_KEY["secrets"].skip_reason)
        # JS analysis runs via should_run check in step_task

        if detected("GraphQL", "Apollo"):
            add("graphql", STEP_BY_KEY["graphql"].reason)
        else:
            skip("graphql", STEP_BY_KEY["graphql"].skip_reason)

        # ── Stack-specific modules ────────────────────
        if detected("Next.js"):
            add("nextjs", STEP_BY_KEY["nextjs"].reason)
        else:
            skip("nextjs", STEP_BY_KEY["nextjs"].skip_reason)
        if detected("Laravel"):
            add("laravel", STEP_BY_KEY["laravel"].reason)
        else:
            skip("laravel", STEP_BY_KEY["laravel"].skip_reason)

        # ── Atlassian ───────────────────────────────
        if detected("Atlassian", "Atlassian Jira", "JIRA", "Confluence", "Bitbucket"):
            add("atlassian", STEP_BY_KEY["atlassian"].reason)
        else:
            skip("atlassian", STEP_BY_KEY["atlassian"].skip_reason)

        if detected("Supabase"):
            add("supabase_rls", STEP_BY_KEY["supabase_rls"].reason)
            add("supabase_rpc", STEP_BY_KEY["supabase_rpc"].reason)
            add("supabase_storage", STEP_BY_KEY["supabase_storage"].reason)
        else:
            skip("supabase_rls", STEP_BY_KEY["supabase_rls"].skip_reason)
            skip("supabase_rpc", STEP_BY_KEY["supabase_rpc"].skip_reason)
            skip("supabase_storage", STEP_BY_KEY["supabase_storage"].skip_reason)

        add("cookies", STEP_BY_KEY["cookies"].reason)
        add("endpoints", STEP_BY_KEY["endpoints"].reason)
        add("wellknown", STEP_BY_KEY["wellknown"].reason)

        try:
            from modules.recon.web.payment_gateway import PaymentGatewayRecon
            pg = PaymentGatewayRecon(self.target)
            payment_signals = {}
            payment_signals.update(pg.from_csp(csp_header) if csp_header else {})
            payment_signals.update(pg.from_html(html) if html else {})
            payment_keys = pg.extract_payment_keys(html) if html else {}
            if payment_signals or payment_keys:
                add("payment", STEP_BY_KEY["payment"].reason)
            else:
                skip("payment", STEP_BY_KEY["payment"].skip_reason)
        except Exception:
            skip("payment", "Payment signal pre-check failed; module can still be selected explicitly.")

        # ── Vuln scanner ─────────────────────────────
        if self.scan_mode == "safe":
            add("vuln", STEP_BY_KEY["vuln"].reason)
            skip("business", STEP_BY_KEY["business"].skip_reason)
        elif has_waf:
            if allow_prompts:
                if self._ask_waf_bypass(waf):
                    add("vuln", "User approved authorized vulnerability scanning despite WAF/CDN signal.")
                    add("business", "User approved authorized business-logic checks despite WAF/CDN signal.")
                else:
                    skip("vuln", "WAF/CDN detected and user declined active vulnerability scanning.")
                    skip("business", "WAF/CDN detected and user declined active business-logic checks.")
            elif self.scan_mode == "aggressive":
                add("vuln", "Aggressive authorized mode allows vulnerability checks behind WAF/CDN.")
                add("business", "Aggressive authorized mode allows business-logic checks behind WAF/CDN.")
            else:
                skip("vuln", "WAF/CDN detected; active mode requires interactive confirmation or aggressive mode.")
                skip("business", "WAF/CDN detected; business-logic checks require confirmation or aggressive mode.")
        else:
            add("vuln", "Authorized active mode and no WAF/CDN block signal detected.")
            add("business", "Authorized active mode and no WAF/CDN block signal detected.")

        if self.scan_mode in ("active", "aggressive"):
            add("admin_scan", STEP_BY_KEY["admin_scan"].reason)
        else:
            skip("admin_scan", STEP_BY_KEY["admin_scan"].skip_reason)

        skip("apk", STEP_BY_KEY["apk"].skip_reason)
        skip("backend_scan", STEP_BY_KEY["backend_scan"].skip_reason)

        # ── CORS Deep Scan ─────────────────────────
        acao = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin", ""))
        if acao:
            add("cors", STEP_BY_KEY["cors"].reason)
        else:
            skip("cors", STEP_BY_KEY["cors"].skip_reason)

        # ── OpenAPI / Swagger ──────────────────────
        api_doc_signals = any(
            kw in html.lower() for kw in
            ["swagger", "openapi", "api-docs", "redoc", "api/documentation"]
        ) if html else False
        if api_doc_signals or detected("Swagger", "Redocly"):
            add("openapi", STEP_BY_KEY["openapi"].reason)
        else:
            skip("openapi", STEP_BY_KEY["openapi"].skip_reason)

        # ── Server Leaks ───────────────────────────
        add("server_leaks", STEP_BY_KEY["server_leaks"].reason)

        # ── API Documentation Discovery ─────────────
        api_doc_signals_help = any(
            kw in html.lower() for kw in
            ["/help", "asp.net web api", "help page", "api documentation",
             "documentation", "/docs", "/developer"]
        ) if html else False
        if api_doc_signals_help or detected("ASP.NET", "ASP.NET Web API", "IIS"):
            add("api_docs", STEP_BY_KEY["api_docs"].reason)
        else:
            skip("api_docs", STEP_BY_KEY["api_docs"].skip_reason)

        # ── Email Security (always runs - baseline) ─
        add("email_recon", STEP_BY_KEY["email_recon"].reason)

        # ── Salesforce ──────────────────────────────
        sf_signals = any(
            kw in html.lower() for kw in
            ["salesforce", "force.com", "visualforce", "apex", "sfdc",
             "lightning", "soql", "my.salesforce.com"]
        ) if html else False
        sf_headers = any(
            "salesforce" in str(v).lower() or "force.com" in str(v).lower()
            for v in headers.values()
        ) if headers else False
        if sf_signals or sf_headers or detected("Salesforce"):
            add("salesforce", STEP_BY_KEY["salesforce"].reason)
        else:
            skip("salesforce", STEP_BY_KEY["salesforce"].skip_reason)

        self._record_smart_plan(plan, reasons, skip_reasons)

        return plan

    def _record_smart_plan(self, plan, reasons, skip_reasons):
        metadata = self.results.setdefault("scan_metadata", {})
        metadata["smart_plan"] = list(plan)
        metadata["smart_plan_reasons"] = dict(reasons)
        metadata["smart_skip_reasons"] = dict(skip_reasons)

    def _smart_add_module(self, smart_plan, module_key: str, reason: str, progress=None, main_task=None):
        if self.enabled_modules is not None or smart_plan is None or module_key in smart_plan:
            return False
        smart_plan.append(module_key)
        metadata = self.results.setdefault("scan_metadata", {})
        metadata.setdefault("smart_plan", list(smart_plan))
        if module_key not in metadata["smart_plan"]:
            metadata["smart_plan"].append(module_key)
        metadata.setdefault("smart_plan_reasons", {})[module_key] = reason
        metadata.setdefault("smart_skip_reasons", {}).pop(module_key, None)
        if progress is not None and main_task is not None:
            total_phases = progress.tasks[main_task].total
            progress.update(main_task, total=total_phases + 1)
        return True

    def _ask_waf_bypass(self, waf: list) -> bool:
        waf_str = ", ".join(waf)
        console.print()
        console.print(Panel(
            "[bold yellow]⚠ WAF Detected:[/bold yellow] " + waf_str + "\n\n"
            "[dim]Vulnerability scan may trigger blocks/bans.[/dim]",
            border_style="yellow"
        ))
        ans = self._input(
            "  [bold white]┃  Continue with vuln scanning? (y/n): [/bold white]"
        , default="n").lower()
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
                f"[bold white]Scan: {self.scan_mode.upper()}[/bold white]  [dim]|[/dim]  "
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
                confirm = self._input(
                    "  Is this correct? "
                    "([bold green]y[/bold green] = yes  /  "
                    "[bold red]n[/bold red] = change): "
                , default="y").lower()

                if confirm in ("y", "yes", ""):
                    break
                elif confirm in ("n", "no"):
                    new_target = self._input(
                        "\n  [bold yellow]→ Enter new target: [/bold yellow]"
                    , default="")
                    if not new_target:
                        console.print("\n  [red]No target entered. Keeping original.[/red]")
                        break
                    valid, reason = validate_target(new_target)
                    if not valid:
                        console.print(f"\n  [red]Invalid target: {reason}[/red]")
                        continue
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
        self.results["scan_metadata"] = {
            "target": self.target,
            "domain": self.domain,
            "scan_mode": self.scan_mode,
            "stealth": self.stealth,
            "redacted_report": self.redact_report,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "requested_modules": sorted(self.enabled_modules) if self.enabled_modules is not None else "smart/full",
        }
        total_steps = planned_total(self.enabled_modules)

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
                skipped_modules.append(key)

            def step_task(module_key: str) -> int:
                nonlocal active_phase_num
                active_phase_num += 1
                name = STEP_TITLES.get(module_key, "Task")
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

            def run_registered_step(module_key: str, result_key: str | None = None,
                                    registry_key: str | None = None,
                                    configure=None, after=None):
                step = STEP_BY_KEY.get(module_key)
                result_name = result_key or (step.output_key if step else module_key)
                lookup_key = registry_key or (step.module_key if step else module_key)
                t = step_task(module_key)
                module_path = MODULES_REGISTRY.get(lookup_key) or STACK_MODULES.get(lookup_key)
                module_obj = self._load_module(module_path) if module_path else None
                if module_obj:
                    if configure:
                        configure(module_obj)
                    self._run_module(result_name, module_obj, progress, t)
                    if after:
                        after(module_obj)
                else:
                    progress.update(t, advance=1)
                _tick(module_key)
                return module_obj

            # ── STEP 1: Basic (ALWAYS) ───────────────────
            run_registered_step('basic')

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

            # ── Handle security block ─────────────────────────────
            if sec_block:
                if auto:
                    progress.console.print(
                        "  [yellow]→ Security block detected; continuing automatically with limited results (--auto)[/yellow]"
                    )
                else:
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
                    choice = self._input(
                        "  [bold white]┃  Your choice (1/2): [/bold white]"
                    , default="1")
                    if choice == "2":
                        console.print("[red]Scan aborted by user.[/red]")
                        return
                    console.print("  [dim]→ Continuing with limited results[/dim]")
                    console.print()
                    progress.start()

            # ── SMART plan override (Full Scan mode = modules is None) ──
            if not auto and self.enabled_modules is None and not sec_block:
                progress.stop()
                smart_plan = self._build_smart_plan(allow_prompts=True)
                progress.start()
            elif auto and self.enabled_modules is None:
                smart_plan = self._build_smart_plan(allow_prompts=False)
            else:
                smart_plan = self.enabled_modules

            if self.enabled_modules is None:
                metadata = self.results.setdefault('scan_metadata', {})
                plan_text = ', '.join(metadata.get('smart_plan', smart_plan or []))
                if plan_text:
                    progress.console.print(f"  [cyan]→ Smart plan ({len(smart_plan or [])} modules): {plan_text}[/cyan]")
                smart_skips = metadata.get('smart_skip_reasons', {})
                if smart_skips:
                    progress.console.print(f"  [dim]→ Smart skipped: {len(smart_skips)} modules with recorded reasons[/dim]")

            progress.update(main_task, total=planned_total(smart_plan))

            def should_run(key: str) -> bool:
                if smart_plan is None:
                    return True
                return key in smart_plan

            # ── STEP 2: Subdomains ───────────────────────
            sub_mod = None
            if should_run('subdomain'):
                def configure_subdomain(mod):
                    mod.domain = self.domain

                def after_subdomain(mod):
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
                            disc = mod.discover_backend_from_ip(bs['ip'])
                            if disc.get('redirect_found'):
                                ip_discoveries.append(disc)
                                progress.console.print(f"    [yellow]⚡ {bs['ip']} → {disc.get('backend_domain')}[/yellow]")
                        if ip_discoveries:
                            self.results['backend_ip_discovery'] = ip_discoveries
                            self.results['subdomain'] = getattr(mod, 'results', self.results.get('subdomain', {}))
                    discovered_subs = self.results.get('subdomain', {}).get('subdomains', [])
                    admin_like = [
                        s for s in discovered_subs
                        if any(word in str(s.get('subdomain', '')).lower()
                               for word in ['admin', 'dashboard', 'portal', 'panel', 'staff', 'sso'])
                    ]
                    if admin_like and self.scan_mode in ("active", "aggressive"):
                        if self._smart_add_module(
                            smart_plan,
                            'admin_scan',
                            f"{len(admin_like)} admin-like subdomain(s) discovered during enumeration.",
                            progress,
                            main_task,
                        ):
                            progress.console.print("  [green]→ Admin-like subdomains detected, enabling admin deep scan[/green]")

                sub_mod = run_registered_step('subdomain', configure=configure_subdomain, after=after_subdomain)
            else:
                _skip("subdomain")

            # ── STEP 3: Cloud ────────────────────────────
            if should_run('cloud'):
                run_registered_step('cloud', configure=lambda mod: setattr(mod, 'domain', self.domain))
            else:
                _skip("cloud")

            # ── STEP 4: JS Analysis ──────────────────────
            if should_run('js'):
                def after_js(_mod):
                    js_apis = self.results.get('js', {}).get('extracted_apis', [])
                    if js_apis and sub_mod is not None:
                        sub_mod.extract_from_js_apis(js_apis)
                        sub_mod.discover_related_domains(js_apis)
                        sub_mod.discover_backends_from_js(js_apis)
                        self.results['subdomain'] = getattr(sub_mod, 'results', self.results.get('subdomain', {}))
                    if js_apis and any('graphql' in a.lower() for a in js_apis):
                        if self._smart_add_module(
                            smart_plan,
                            'graphql',
                            "GraphQL endpoint discovered in JavaScript assets.",
                            progress,
                            main_task,
                        ):
                            progress.console.print("  [green]→ GraphQL endpoints detected in JS, enabling graphql module[/green]")
                    mobile_apps = self.results.get('js', {}).get('mobile_apps', {})
                    if mobile_apps:
                        if self._smart_add_module(
                            smart_plan,
                            'apk',
                            STEP_BY_KEY["apk"].reason,
                            progress,
                            main_task,
                        ):
                            progress.console.print("  [green]→ Mobile app references detected, enabling APK/mobile analysis[/green]")

                run_registered_step('js', after=after_js)
            else:
                _skip("js")

            # ── STEP 5: GraphQL ──────────────────────────
            if should_run('graphql'):
                run_registered_step('graphql')
            else:
                _skip("graphql")

            # ── STEP 6: Secrets ──────────────────────────
            if should_run('secrets'):
                run_registered_step('secrets')
            else:
                _skip("secrets")

            # Stack-specific module (Next.js / Laravel)
            det_stack = self.results.get('detected_stack', [])
            if "Next.js" in det_stack and should_run('nextjs'):
                def configure_nextjs(mod):
                    basic_html    = self.results.get('basic', {}).get('_html', '')
                    raw_headers   = self.results.get('basic', {}).get('headers', {}).get('_raw_headers', {})
                    if basic_html and hasattr(mod, 'set_initial_response'):
                        mod.set_initial_response(basic_html, raw_headers)

                run_registered_step('nextjs', registry_key='Next.js', configure=configure_nextjs)
            elif should_run('nextjs'):
                _skip("nextjs")

            if "Laravel" in det_stack and should_run('laravel'):
                run_registered_step('laravel', registry_key='Laravel')
            elif should_run('laravel'):
                _skip("laravel")

            atlassian_techs = {"Atlassian Jira", "JIRA", "Confluence", "Bitbucket", "Atlassian"}
            if atlassian_techs & set(tech_names) and should_run('atlassian'):
                def configure_atlassian(mod):
                    if hasattr(mod, 'set_initial_response'):
                        basic_html = self.results.get('basic', {}).get('_html', '')
                        raw_headers = self.results.get('basic', {}).get('headers', {}).get('_raw_headers', {})
                        if basic_html:
                            mod.set_initial_response(basic_html, raw_headers)
                run_registered_step('atlassian', registry_key='Atlassian', configure=configure_atlassian)
                if 'Jira' in str(tech_names):
                    atl_results = self.results.get('atlassian', {})
                    jira = atl_results.get('jira', {})
                    anon = atl_results.get('anonymous_access', {})
                    if anon:
                        progress.console.print(f"  [bold red]⚠ Jira anonymous access detected: {len(anon)} accessible endpoint(s)[/bold red]")
                        for ep, info in list(anon.items())[:3]:
                            progress.console.print(f"    [dim]→ {ep}: {info.get('data','')[:80]}[/dim]")
                    server_info = jira.get('/rest/api/2/serverInfo', {})
                    if server_info.get('version'):
                        progress.console.print(f"  [yellow]Jira {server_info['version']} ({server_info.get('deployment','?')}) exposed[/yellow]")
            elif should_run('atlassian'):
                _skip("atlassian")

            # ── STEP 7: Vuln Scanner ─────────────────────
            if should_run('vuln'):
                run_registered_step('vuln')
            else:
                _skip("vuln")

            # ── STEP 8: Business Logic ───────────────────
            if should_run('business'):
                run_registered_step('business')
            else:
                _skip("business")

            # ── STEP 9: Cookies ──────────────────────────
            if should_run('cookies'):
                run_registered_step('cookies')
            else:
                _skip("cookies")

            # ── STEP 10: DNS ─────────────────────────────
            if should_run('dns'):
                run_registered_step('dns')
            else:
                _skip("dns")

            # ── STEP 11: Endpoints ───────────────────────
            if should_run('endpoints'):
                run_registered_step('endpoints')
            else:
                _skip("endpoints")

            # ── STEP 12: Payment Gateway / Billing Surface ─────────
            if should_run('payment'):
                def configure_payment(mod):
                    basic_html = self.results.get('basic', {}).get('_html', '')
                    basic_headers = self.results.get('basic', {}).get('headers', {})
                    csp_header = basic_headers.get('Content-Security-Policy', basic_headers.get('content-security-policy', ''))
                    if hasattr(mod, 'set_initial_response'):
                        mod.set_initial_response(basic_html, csp_header)

                def after_payment(_mod):
                    pg_results = self.results.get('payment_gateway', {})
                    gateways = list(pg_results.get('csp_analysis', {}).keys()) if isinstance(pg_results, dict) else []
                    if gateways:
                        progress.console.print(f"  [green]Payment gateways: {', '.join(gateways)}[/green]")
                    keys = pg_results.get('payment_keys', {}) if isinstance(pg_results, dict) else {}
                    if keys:
                        for provider, key_list in keys.items():
                            for k in key_list:
                                if isinstance(k, dict):
                                    progress.console.print(f"  [yellow]{provider} key ({k.get('mode','?')}/{k.get('type','?')})[/yellow]")

                run_registered_step('payment', configure=configure_payment, after=after_payment)
            else:
                _skip("payment")

            # ── STEP 13: Supabase RLS Testing ──────────────
            if should_run('supabase_rls'):
                def after_supabase_rls(_mod):
                    open_tables = self.results.get('supabase_rls', {}).get('rls_open_tables', [])
                    if open_tables:
                        progress.console.print(f"  [bold red]⚠ {len(open_tables)} Supabase tables accessible with anon_key![/bold red]")

                run_registered_step('supabase_rls', after=after_supabase_rls)
            else:
                _skip("supabase_rls")

            # ── STEP 13: Supabase RPC Enumeration ──────────
            if should_run('supabase_rpc'):
                def after_supabase_rpc(_mod):
                    exposed_rpcs = self.results.get('supabase_rpc', {}).get('rpc_exposed', [])
                    if exposed_rpcs:
                        progress.console.print(f"  [bold yellow]⚡ {len(exposed_rpcs)} Supabase RPC functions discovered[/bold yellow]")

                run_registered_step('supabase_rpc', after=after_supabase_rpc)
            else:
                _skip("supabase_rpc")

            # ── STEP 14: Supabase Storage Audit ────────────
            if should_run('supabase_storage'):
                def after_supabase_storage(_mod):
                    public_buckets = self.results.get('supabase_storage', {}).get('public_buckets', [])
                    if public_buckets:
                        progress.console.print(f"  [bold red]⚠ {len(public_buckets)} public Supabase storage buckets found![/bold red]")

                run_registered_step('supabase_storage', after=after_supabase_storage)
            else:
                _skip("supabase_storage")

            # ── STEP 15: Well-Known Discovery ──────────────
            if should_run('wellknown'):
                def after_wellknown(_mod):
                    llms = self.results.get('wellknown', {}).get('llms_txt_found', [])
                    if llms:
                        progress.console.print(f"  [bold yellow]📄 llms.txt found! Potential intelligence source[/bold yellow]")

                run_registered_step('wellknown', after=after_wellknown)
            else:
                _skip("wellknown")

            # ── STEP 16: APK Analysis ──────────────────────
            if should_run('apk'):
                def after_apk(_mod):
                    apk_refs = self.results.get('apk', {}).get('apk_references', [])
                    if apk_refs:
                        progress.console.print(f"  [green]📱 {len(apk_refs)} APK/App references found[/green]")
                    apk_keys = self.results.get('apk', {}).get('apk_secrets', [])
                    if apk_keys:
                        progress.console.print(f"  [bold yellow]🔑 {len(apk_keys)} potential secrets extracted from APK[/bold yellow]")

                run_registered_step('apk', after=after_apk)
            else:
                _skip("apk")

            # ── STEP 17: DNS Detritus Detection ───────────
            if should_run('dns_detritus'):
                def after_dns_detritus(_mod):
                    total = self.results.get('dns_detritus', {}).get('total_detritus', 0)
                    if total:
                        progress.console.print(f"  [bold yellow]🗑️ {total} DNS detritus records found[/bold yellow]")

                run_registered_step('dns_detritus', after=after_dns_detritus)
            else:
                _skip("dns_detritus")

            # ── STEP 18: Admin Subdomain Deep Scan ────────
            if should_run('admin_scan'):
                def after_admin_scan(_mod):
                    admin_subs = self.results.get('admin_scan', {}).get('admin_subdomains', [])
                    if admin_subs:
                        progress.console.print(f"  [bold yellow]🔐 {len(admin_subs)} admin subdomains discovered[/bold yellow]")
                    accessible = self.results.get('admin_scan', {}).get('accessible_admin', [])
                    if accessible:
                        progress.console.print(f"  [bold red]⚠ {len(accessible)} admin subdomains potentially accessible![/bold red]")

                run_registered_step('admin_scan', after=after_admin_scan)
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
            if real_backends:
                self._smart_add_module(
                    smart_plan,
                    'backend_scan',
                    f"{len(real_backends)} backend/API host reference(s) discovered.",
                    progress,
                    main_task,
                )
            if should_run('backend_scan'):
                if real_backends:
                    progress.console.print(f"  [bold cyan]⚡ Scanning {len(real_backends)} backend server(s) for APIs...[/bold cyan]")

                def configure_backend_scan(mod):
                    if hasattr(mod, 'set_backends'):
                        mod.set_backends(real_backends, self.domain)

                def after_backend_scan(_mod):
                    scanned = self.results.get('backend_scan', {}).get('scanned_backends', {})
                    for backend_url in list(scanned.keys())[:3]:
                        progress.console.print(f"    [dim]→ {backend_url}[/dim]")

                run_registered_step('backend_scan', configure=configure_backend_scan, after=after_backend_scan)

            # ── STEP 20: CORS Deep Scan ──────────────────────
            if should_run('cors'):
                def after_cors(_mod):
                    cors_findings = self.results.get('cors', {})
                    misconfigs = cors_findings.get('misconfigurations', [])
                    if misconfigs:
                        critical = [m for m in misconfigs if m.get('severity') == 'CRITICAL']
                        high = [m for m in misconfigs if m.get('severity') == 'HIGH']
                        if critical:
                            progress.console.print(f"  [bold red]⚠ {len(critical)} CRITICAL CORS misconfiguration(s)![/bold red]")
                        if high:
                            progress.console.print(f"  [bold yellow]⚠ {len(high)} HIGH-severity CORS issue(s)[/bold yellow]")
                        progress.console.print(f"  [yellow]→ {len(misconfigs)} total CORS misconfiguration(s) found[/yellow]")

                run_registered_step('cors', after=after_cors)
            else:
                _skip("cors")

            # ── STEP 21: OpenAPI / Swagger Discovery ─────────
            if should_run('openapi'):
                def after_openapi(_mod):
                    oa_findings = self.results.get('openapi', {})
                    if oa_findings.get('spec_found'):
                        progress.console.print(f"  [green]✓ OpenAPI spec(s) found: {len(oa_findings.get('specs', []))}[/green]")
                        total = oa_findings.get('total_endpoints', 0)
                        progress.console.print(f"  [cyan]📊 {total} API endpoints documented in spec[/cyan]")
                        unauth = oa_findings.get('unauthenticated_endpoints', [])
                        if unauth:
                            progress.console.print(f"  [bold yellow]⚠ {len(unauth)} endpoint(s) without auth requirement[/bold yellow]")
                        sensitive = oa_findings.get('sensitive_operations', [])
                        if sensitive:
                            progress.console.print(f"  [bold red]🚨 {len(sensitive)} sensitive operation(s) in API spec[/bold red]")

                run_registered_step('openapi', after=after_openapi)
            else:
                _skip("openapi")

            # ── STEP 22: Server Leak & Environment Detection ─
            if should_run('server_leaks'):
                def after_server_leaks(_mod):
                    sl_findings = self.results.get('server_leaks', {})
                    leaky = sl_findings.get('leaky_headers', {})
                    if leaky:
                        progress.console.print(f"  [yellow]📡 {len(leaky)} leaky header(s) detected[/yellow]")
                    env = sl_findings.get('environment_detected')
                    if env:
                        progress.console.print(f"  [bold cyan]🏭 Environment detected: {env}[/bold cyan]")
                    regions = sl_findings.get('internal_regions', [])
                    if regions:
                        progress.console.print(f"  [dim]🌍 Internal regions/DCs: {', '.join(regions)}[/dim]")
                    timing = sl_findings.get('server_timing_analysis', {})
                    internal_params = timing.get('internal_params', [])
                    if internal_params:
                        for param in internal_params:
                            label = param.get('internal_label', param.get('key', ''))
                            value = param.get('value', '')
                            progress.console.print(f"    [dim]⏱ {label}: {value}[/dim]")
                    versions = sl_findings.get('version_disclosures', [])
                    if versions:
                        version_str = ', '.join(f"{v['header']}: {v['version']}" for v in versions[:3])
                        progress.console.print(f"  [yellow]ℹ Version leaks: {version_str}[/yellow]")

                run_registered_step('server_leaks', after=after_server_leaks)
            else:
                _skip("server_leaks")

            # ── STEP 23: API Documentation Discovery ─────────
            if should_run('api_docs'):
                def after_api_docs(_mod):
                    ad = self.results.get('api_docs', {})
                    total = ad.get('total_endpoints_found', 0)
                    if total:
                        progress.console.print(f"  [bold yellow]📚 {total} API endpoints discovered from doc pages[/bold yellow]")
                    doc_count = ad.get('doc_pages_discovered', 0)
                    if doc_count:
                        progress.console.print(f"  [cyan]→ {doc_count} documentation page(s) found[/cyan]")
                    help_type = ad.get('help_type', '')
                    if help_type == 'aspnet_web_api':
                        aspnet = ad.get('aspnet_help', {})
                        controllers = aspnet.get('controllers', [])
                        unauth = aspnet.get('unauthenticated_endpoints', 0)
                        if controllers:
                            progress.console.print(f"  [cyan]→ ASP.NET Controllers ({len(controllers)}): {', '.join(controllers[:8])}[/cyan]")
                        if unauth:
                            progress.console.print(f"  [bold red]⚠ {unauth} endpoints potentially unauthenticated[/bold red]")

                run_registered_step('api_docs', after=after_api_docs)
            else:
                _skip("api_docs")

            # ── STEP 24: Email Security Recon ─────────────────
            if should_run('email_recon'):
                def after_email_recon(_mod):
                    er = self.results.get('email_recon', {})
                    mx = er.get('mx', {}).get('records', [])
                    if mx:
                        mx_servers = [f"{m['server']}({m['priority']})" for m in mx[:3]]
                        progress.console.print(f"  [cyan]📧 MX: {', '.join(mx_servers)}[/cyan]")
                    spf = er.get('spf', {})
                    spf_sev = spf.get('severity', '')
                    if spf_sev == 'HIGH':
                        progress.console.print(f"  [bold red]⚠ SPF: {spf.get('note', 'Issue detected')}[/bold red]")
                    elif spf_sev:
                        progress.console.print(f"  [yellow]📜 SPF: {spf_sev} — {spf.get('note', '')[:80]}[/yellow]")
                    dmarc = er.get('dmarc', {})
                    dmarc_sev = dmarc.get('severity', '')
                    if dmarc_sev == 'HIGH':
                        progress.console.print(f"  [bold red]⚠ DMARC: {dmarc.get('note', 'Issue detected')}[/bold red]")
                    elif dmarc_sev:
                        progress.console.print(f"  [yellow]📜 DMARC: {dmarc_sev} — {dmarc.get('policy', '?')}[/yellow]")
                    dkim = er.get('dkim', {})
                    if dkim.get('total_found', 0):
                        progress.console.print(f"  [green]🔑 DKIM: {dkim['total_found']} selector(s) found[/green]")
                    summary = er.get('security_summary', {})
                    if summary.get('score') is not None:
                        score = summary['score']
                        rating = summary.get('rating', '?')
                        color = 'green' if score >= 8 else 'yellow' if score >= 5 else 'red'
                        progress.console.print(f"  [bold {color}]📊 Email Security Score: {score}/10 ({rating})[/bold {color}]")

                run_registered_step('email_recon', after=after_email_recon)
            else:
                _skip("email_recon")

            # ── STEP 25: Salesforce Instance Detection ────────
            if should_run('salesforce'):
                def after_salesforce(_mod):
                    sf = self.results.get('salesforce', {})
                    if sf.get('detected'):
                        progress.console.print(f"  [bold yellow]☁️ Salesforce detected![/bold yellow]")
                        header_det = sf.get('header_detection', {}).get('headers_found', {})
                        if header_det:
                            hdr_str = '; '.join(f"{k}: {v}" for k, v in list(header_det.items())[:3])
                            progress.console.print(f"    [dim]Headers: {hdr_str}[/dim]")
                        html_ind = sf.get('html_detection', {}).get('indicators', [])
                        if html_ind:
                            progress.console.print(f"    [dim]HTML indicators: {', '.join(html_ind[:5])}[/dim]")
                        subs = sf.get('subdomains', {}).get('subdomains', [])
                        sf_subs = [s for s in subs if s.get('is_salesforce')]
                        if sf_subs:
                            progress.console.print(f"  [cyan]→ {len(sf_subs)} Salesforce subdomain(s) detected[/cyan]")
                        versions = sf.get('api_versions', {}).get('versions', [])
                        if versions:
                            ver_str = ', '.join(v['version'] for v in versions[:3])
                            progress.console.print(f"  [cyan]→ API versions: {ver_str}[/cyan]")
                    else:
                        progress.console.print(f"  [dim]→ No Salesforce indicators found[/dim]")

                run_registered_step('salesforce', after=after_salesforce)
            else:
                _skip("salesforce")

            # Final summary of skipped modules
            metadata = self.results.setdefault('scan_metadata', {})
            if self.enabled_modules is None:
                skipped_for_report = sorted(metadata.get('smart_skip_reasons', {}).keys() or skipped_modules)
            else:
                skipped_for_report = skipped_modules
            if skipped_for_report:
                metadata['not_selected_or_skipped_modules'] = skipped_for_report
                if self.enabled_modules is not None:
                    requested = ', '.join(sorted(self.enabled_modules))
                    progress.console.print(
                        f"  [dim]→ Not selected: {len(skipped_for_report)} modules "
                        f"(requested: {requested})[/dim]"
                    )
                else:
                    progress.console.print(f"  [dim]→ Smart skipped ({len(skipped_for_report)} modules): {', '.join(skipped_for_report)}[/dim]")

            # Finalize progress bar to 100%
            progress.update(main_task, completed=progress.tasks[main_task].total,
                            description="[bold green]Overall Progress — 100%  ✓ Done[/bold green]")


        console.print()
        self.display_summary()
        self.save_results()

    def display_summary(self):
        display_summary(self.results, self.domain, console)

    def save_results(self):
        return save_scan_results(
            self.results,
            self.domain,
            redact_report=self.redact_report,
            console=console,
        )


def main():
    run_cli(NexusREC, console, BANNER, LINKS)

if __name__ == "__main__":
    main()
