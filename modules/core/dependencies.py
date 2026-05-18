import importlib.util
import sys


REQUIRED_DEPENDENCIES = {
    "requests": {
        "import": "requests",
        "install": "requests==2.31.0",
        "used_by": "HTTP-based recon modules",
    },
    "rich": {
        "import": "rich",
        "install": "rich==13.7.1",
        "used_by": "terminal UI and progress rendering",
    },
    "urllib3": {
        "import": "urllib3",
        "install": "urllib3",
        "used_by": "TLS warning handling and requests transport",
    },
}

OPTIONAL_DEPENDENCIES = {
    "dnspython": {
        "import": "dns.resolver",
        "install": "dnspython",
        "used_by": "DNS MX detritus checks",
    },
}


def _available(import_name):
    try:
        return importlib.util.find_spec(import_name) is not None
    except ModuleNotFoundError:
        return False


def _missing(dependencies):
    missing = []
    for name, info in dependencies.items():
        if not _available(info["import"]):
            missing.append({
                "name": name,
                "install": info["install"],
                "used_by": info["used_by"],
            })
    return missing


def check_dependencies(console=None, exit_on_missing_required=False, include_optional=True):
    required_missing = _missing(REQUIRED_DEPENDENCIES)
    optional_missing = _missing(OPTIONAL_DEPENDENCIES) if include_optional else []

    if console and (required_missing or optional_missing):
        console.print("\n[bold yellow]Dependency check[/bold yellow]")
        if required_missing:
            console.print("[bold red]Missing required package(s):[/bold red]")
            for dep in required_missing:
                console.print(f"  [red]- {dep['name']}[/red] ({dep['used_by']})")
        if optional_missing:
            console.print("[bold yellow]Missing optional package(s):[/bold yellow]")
            for dep in optional_missing:
                console.print(f"  [yellow]- {dep['name']}[/yellow] ({dep['used_by']})")
        install_items = [dep["install"] for dep in required_missing + optional_missing]
        if install_items:
            console.print("\nInstall suggestion:")
            console.print(f"  [bold]python3 -m pip install {' '.join(install_items)}[/bold]\n")

    if required_missing and exit_on_missing_required:
        sys.exit(2)

    return {
        "required_missing": required_missing,
        "optional_missing": optional_missing,
        "ok": not required_missing,
    }
