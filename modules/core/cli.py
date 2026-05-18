import argparse
import re
import sys
from urllib.parse import urlparse

from rich.align import Align
from rich.panel import Panel
from rich.table import Table

from modules.core.config import MODULES_REGISTRY, SCAN_MODES, VERSION

VALID_MODULES = set(MODULES_REGISTRY) | {"nextjs", "laravel"}


def build_parser():
    parser = argparse.ArgumentParser(
        description="Nexus-REC v1.0 — Modular Reconnaissance & Vulnerability Assessment Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com --stealth
  %(prog)s example.com --scan-mode active --i-have-authorization
  %(prog)s example.com --modules basic,js,vuln

Author: Ihsan Alapsi — https://github.com/ihsanalapsi/Nexus-REC
        """
    )
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
        "--scan-mode", choices=SCAN_MODES, default="safe",
        help="Scan intensity. safe avoids state-changing checks; active enables authorized vulnerability payloads; aggressive adds higher-noise checks."
    )
    parser.add_argument(
        "--i-have-authorization", action="store_true",
        help="Confirm you are authorized to run active/aggressive tests against the target."
    )
    parser.add_argument(
        "--redact-report", action="store_true",
        help="Also write a shareable redacted JSON report. The raw report is always saved."
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
    parser.add_argument(
        "--debug", action="store_true",
        help="Show full Python tracebacks for unexpected errors."
    )
    return parser


def validate_target(target):
    if not target or not target.strip():
        return False, "Target cannot be empty."
    target = target.strip()
    if any(ch.isspace() for ch in target):
        return False, "Target must not contain spaces."
    if target.startswith("-"):
        return False, "Target must not start with '-'."

    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.netloc.split("@")[-1].split(":")[0]
    if not host:
        return False, "Target must include a hostname or IP address."
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True, ""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        parts = [int(p) for p in host.split(".")]
        if all(0 <= p <= 255 for p in parts):
            return True, ""
        return False, "IP address octets must be between 0 and 255."
    if "." not in host:
        return False, "Domain targets should include a dot, e.g. example.com."
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return False, "Hostname contains unsupported characters."
    return True, ""


def safe_input(console, prompt, default=None):
    try:
        value = console.input(prompt).strip()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]⛔ Cancelled.[/bold red]")
        sys.exit(0)
    except EOFError:
        if default is not None:
            return default
        console.print("\n[red]Input stream closed. Exiting safely.[/red]")
        sys.exit(1)
    return value


def ask_yes_no(console, prompt, default=False):
    suffix = "Y/n" if default else "y/N"
    while True:
        answer = safe_input(console, f"{prompt} [dim]({suffix})[/dim]: ", default="").lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        console.print("[red]Please answer y or n.[/red]")


def prompt_for_target(args, console, banner, links):
    if args.target:
        return args

    grid = Table.grid(expand=True)
    grid.add_column(ratio=10)
    grid.add_column(ratio=1, justify="center")
    grid.add_column(ratio=10)

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
        "[dim]--auto | --stealth | --scan-mode | --modules[/dim]"
    )

    grid.add_row(info_side, separator, usage_side)
    main_panel = Panel(
        grid,
        title=f"[bold white] NEXUS-REC v{VERSION} [/bold white]",
        border_style="bright_green",
        padding=(1, 4),
        width=90,
    )

    console.clear()
    console.print(Align.center(banner))
    console.print(Align.center(links))
    console.print()
    console.print(Align.center(main_panel))

    while True:
        target_input = safe_input(
            console,
            "\n  [bold bright_green]→[/bold bright_green] [bold white]Enter target domain or URL:[/bold white] "
        )
        valid, reason = validate_target(target_input)
        if valid:
            break
        console.print(f"[red]  Invalid target: {reason}[/red]")

    args.target = target_input
    console.print()
    return args


def prompt_for_interactive_options(args, console):
    console.print("[bold cyan]Interactive Options[/bold cyan]")
    mode_choices = ", ".join(SCAN_MODES)
    while True:
        scan_mode = safe_input(
            console,
            f"  [bold white]Scan mode[/bold white] [dim]({mode_choices}, default: safe):[/dim] ",
            default="safe",
        ).lower() or "safe"
        if scan_mode in SCAN_MODES:
            args.scan_mode = scan_mode
            break
        console.print(f"[red]Invalid scan mode. Choose one of: {mode_choices}[/red]")

    args.stealth = ask_yes_no(console, "  Enable stealth mode?", default=False)
    args.redact_report = ask_yes_no(console, "  Also create redacted shareable report?", default=False)
    if args.scan_mode in ("active", "aggressive"):
        args.i_have_authorization = ask_yes_no(
            console,
            "  Confirm you are authorized to run active/aggressive tests?",
            default=False,
        )
    console.print()
    return args


def resolve_enabled_modules(modules_arg, parser=None):
    if modules_arg and modules_arg != 'all':
        enabled = {m.strip().lower() for m in modules_arg.split(',') if m.strip()}
        invalid = sorted(enabled - VALID_MODULES)
        if invalid:
            message = (
                f"Invalid module(s): {', '.join(invalid)}. "
                f"Valid modules: {', '.join(sorted(VALID_MODULES))}"
            )
            if parser:
                parser.error(message)
            raise ValueError(message)
        return enabled
    return None


def enforce_authorization(args, console):
    if args.scan_mode in ("active", "aggressive") and not args.i_have_authorization:
        console.print(
            "[bold red]Active/aggressive scans require authorization confirmation.[/bold red]\n"
            "Re-run with [bold]--i-have-authorization[/bold] if this target is in scope."
        )
        sys.exit(2)


def run_cli(recon_cls, console, banner, links, argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    interactive_launch = args.target is None
    args = prompt_for_target(args, console, banner, links)
    valid, reason = validate_target(args.target)
    if not valid:
        parser.error(f"invalid target: {reason}")
    if interactive_launch:
        args = prompt_for_interactive_options(args, console)
    enabled = resolve_enabled_modules(args.modules, parser)
    enforce_authorization(args, console)

    try:
        recon = recon_cls(
            args.target,
            stealth=args.stealth,
            enabled_modules=enabled,
            scan_mode=args.scan_mode,
            redact_report=args.redact_report,
        )
        recon.run(auto=args.auto)
    except KeyboardInterrupt:
        console.print("\n\n[bold red]⛔ Scan interrupted by user.[/bold red]")
        sys.exit(0)
    except Exception as e:
        if args.debug:
            raise
        console.print(f"\n[bold red]Unexpected error:[/bold red] {e}")
        console.print("[dim]Re-run with --debug to see the full traceback.[/dim]")
        sys.exit(1)
