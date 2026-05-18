import importlib


def load_module(module_path, target, scan_mode="safe", stealth=False, console=None):
    try:
        parts = module_path.split('.')
        class_name = parts[-1]
        module_name = '.'.join(parts[:-1])
        mod = importlib.import_module(module_name)
        cls = getattr(mod, class_name)
        module_obj = cls(target)
        configure_module(module_obj, scan_mode=scan_mode, stealth=stealth)
        return module_obj
    except Exception as e:
        if console:
            console.print(f"[red]Failed to load {module_path}: {e}[/red]")
        return None


def configure_module(module_obj, scan_mode="safe", stealth=False):
    setattr(module_obj, "scan_mode", scan_mode)
    setattr(module_obj, "stealth", stealth)
    setattr(module_obj, "max_workers", 3 if stealth else 8)
    setattr(module_obj, "request_delay", 1.25 if stealth else 0)
    return module_obj
