#!/usr/bin/env python3
import requests
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

        add("subdomain", "Baseline external surface mapping after fingerprinting.")
        add("cloud", "Baseline CDN/cloud and bucket exposure checks.")
        add("dns", "Baseline DNS, SSL, and port posture checks.")
        add("dns_detritus", "DNS-based stale record and legacy host checks are useful without HTTP access.")

        if security_block:
            block_reason = f"Security challenge detected ({security_block}); HTTP-heavy module likely blocked."
            for key in [
                "js", "graphql", "secrets", "vuln", "business", "cookies",
                "endpoints", "payment", "supabase_rls", "supabase_rpc",
                "supabase_storage", "wellknown", "apk", "admin_scan",
                "nextjs", "laravel",
            ]:
                skip(key, block_reason)
            self._record_smart_plan(plan, reasons, skip_reasons)
            return plan

        js_techs = ["React", "Next.js", "Vue.js", "Nuxt.js", "Angular",
                    "Svelte", "Webpack", "Vite", "JavaScript"]
        if any(t in tech_names for t in js_techs) or has_js_from_html:
            add("js", "JavaScript framework/assets detected in fingerprinting or HTML.")
            add("secrets", "Client assets may expose public config, endpoints, or accidental secrets.")
        else:
            skip("js", "No JavaScript framework or bundle indicators were detected.")
            skip("secrets", "Secret scanning depends on HTML/JS assets; no useful asset signal was found.")
        # JS analysis runs via should_run check in step_task

        if detected("GraphQL", "Apollo"):
            add("graphql", "GraphQL/Apollo technology was detected during fingerprinting.")
        else:
            skip("graphql", "No GraphQL/Apollo signal was detected before JS extraction.")

        # ── Stack-specific modules ────────────────────
        if detected("Next.js"):
            add("nextjs", "Next.js detected; framework-specific routes/assets checks are relevant.")
        else:
            skip("nextjs", "Next.js was not detected.")
        if detected("Laravel"):
            add("laravel", "Laravel detected; framework-specific debug/route checks are relevant.")
        else:
            skip("laravel", "Laravel was not detected.")

        if detected("Supabase"):
            add("supabase_rls", "Supabase detected; anon/RLS exposure checks are relevant.")
            add("supabase_rpc", "Supabase detected; RPC exposure checks are relevant.")
            add("supabase_storage", "Supabase detected; storage bucket exposure checks are relevant.")
        else:
            skip("supabase_rls", "Supabase was not detected.")
            skip("supabase_rpc", "Supabase was not detected.")
            skip("supabase_storage", "Supabase was not detected.")

        add("cookies", "Session and CSRF posture is relevant for web targets.")
        add("endpoints", "Endpoint discovery is relevant after fingerprinting and asset extraction.")
        add("wellknown", "Well-known files, security.txt, and llms.txt are low-impact intelligence sources.")

        try:
            from modules.recon.payment_gateway import PaymentGatewayRecon
            pg = PaymentGatewayRecon(self.target)
            payment_signals = {}
            payment_signals.update(pg.from_csp(csp_header) if csp_header else {})
            payment_signals.update(pg.from_html(html) if html else {})
            payment_keys = pg.extract_payment_keys(html) if html else {}
            if payment_signals or payment_keys:
                add("payment", "Payment gateway domains/scripts/keys were detected in CSP or HTML.")
            else:
                skip("payment", "No payment gateway indicators were detected in CSP or HTML.")
        except Exception:
            skip("payment", "Payment signal pre-check failed; module can still be selected explicitly.")

        # ── Vuln scanner ─────────────────────────────
        if self.scan_mode == "safe":
            add("vuln", "Safe vulnerability checks are allowed in safe mode; active payloads remain gated.")
            skip("business", "Business-logic probes require active/aggressive authorized mode.")
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
            add("admin_scan", "Authorized active mode allows deeper admin surface discovery.")
        else:
            skip("admin_scan", "Admin deep scan is held for active/aggressive authorized mode or later discovery.")

        skip("apk", "Mobile app references are checked after JavaScript/HTML discovery.")

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
            "payment":         "Payment Gateway & Billing Surface",
            "supabase_rls":    "Supabase RLS Policy Testing",
            "supabase_rpc":    "Supabase RPC Enumeration",
            "supabase_storage":"Supabase Storage Audit",
            "wellknown":       "Well-Known / llms.txt Discovery",
            "apk":             "APK Analysis",
            "dns_detritus":    "DNS Detritus Detection",
            "admin_scan":      "Admin Subdomain Deep Scan",
        }

        execution_order = list(ALL_STEPS.keys())

        def _planned_total(plan, detected_stack=None):
            if plan is None:
                return len(execution_order)
            planned = set(plan)
            planned.add('basic')
            total = sum(1 for key in execution_order if key in planned)
            detected_stack = detected_stack or []
            if "Next.js" in detected_stack and 'nextjs' in planned:
                total += 1
            elif "Laravel" in detected_stack and 'laravel' in planned:
                total += 1
            return max(1, total)

        total_steps = _planned_total(self.enabled_modules)

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

            progress.update(main_task, total=_planned_total(smart_plan, self.results.get('detected_stack', [])))

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
                        "Mobile app references discovered in JavaScript/HTML metadata.",
                        progress,
                        main_task,
                    ):
                        progress.console.print("  [green]→ Mobile app references detected, enabling APK/mobile analysis[/green]")
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
                    _tick("nextjs")
            elif should_run('nextjs'):
                _skip("nextjs")

            if "Laravel" in det_stack and should_run('laravel'):
                laravel_mod = self._load_module(STACK_MODULES['Laravel'])
                if laravel_mod:
                    t_lv = step_task('laravel')
                    self._run_module('laravel', laravel_mod, progress, t_lv)
                    _tick("laravel")
            elif should_run('laravel'):
                _skip("laravel")

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

            # ── STEP 12: Payment Gateway / Billing Surface ─────────
            if should_run('payment'):
                t = step_task('payment')
                try:
                    from modules.recon.payment_gateway import PaymentGatewayRecon
                    basic_html = self.results.get('basic', {}).get('_html', '')
                    basic_headers = self.results.get('basic', {}).get('headers', {})
                    csp_header = basic_headers.get('Content-Security-Policy', basic_headers.get('content-security-policy', ''))
                    pg = PaymentGatewayRecon(self.target)
                    pg_results = pg.run_all(html=basic_html, csp=csp_header, base_url=self.target)
                    self.results['payment_gateway'] = pg_results
                    completed_sections = self.results.setdefault('scan_metadata', {}).setdefault('completed_result_sections', [])
                    if 'payment_gateway' not in completed_sections:
                        completed_sections.append('payment_gateway')
                    gateways = list(pg_results.get('csp_analysis', {}).keys())
                    if gateways:
                        progress.console.print(f"  [green]Payment gateways: {', '.join(gateways)}[/green]")
                    keys = pg_results.get('payment_keys', {})
                    if keys:
                        for provider, key_list in keys.items():
                            for k in key_list:
                                if isinstance(k, dict):
                                    progress.console.print(f"  [yellow]{provider} key ({k.get('mode','?')}/{k.get('type','?')})[/yellow]")
                    progress.update(t, advance=1)
                except Exception as exc:
                    self.results['payment_gateway'] = {'error': str(exc)}
                    progress.update(t, advance=1)
                _tick("payment")
            else:
                _skip("payment")

            # ── STEP 13: Supabase RLS Testing ──────────────
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


if __name__ == "__main__":
    run_cli(NexusREC, console, BANNER, LINKS)
