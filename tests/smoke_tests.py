import importlib
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.core.config import MODULES_REGISTRY, STACK_MODULES
from modules.core.pipeline import STEP_BY_KEY, planned_total
from nexus_rec import NexusREC


class RegistrySmokeTests(unittest.TestCase):
    def test_all_registry_paths_import(self):
        for key, dotted_path in {**MODULES_REGISTRY, **STACK_MODULES}.items():
            with self.subTest(key=key):
                module_name, class_name = dotted_path.rsplit(".", 1)
                module = importlib.import_module(module_name)
                self.assertTrue(hasattr(module, class_name))

    def test_pipeline_has_registry_coverage(self):
        for key in MODULES_REGISTRY:
            with self.subTest(key=key):
                self.assertIn(key, STEP_BY_KEY)

    def test_planned_total_counts_requested_steps(self):
        self.assertEqual(planned_total({"basic"}), 1)
        self.assertEqual(planned_total({"basic", "payment", "backend_scan"}), 3)


class SmartPlanSmokeTests(unittest.TestCase):
    def test_supabase_nextjs_payment_plan(self):
        recon = NexusREC("https://symarket.app")
        recon.results = {
            "scan_metadata": {},
            "detected_stack": ["Supabase", "Next.js", "React"],
            "basic": {
                "technologies": {"Supabase": "x", "Next.js": "x", "React": "x"},
                "headers": {"Content-Security-Policy": "script-src https://js.stripe.com"},
                "_html": '<div id="__next"></div>',
                "waf": ["None Detected"],
            },
        }
        plan = recon._build_smart_plan(allow_prompts=False)
        self.assertIn("nextjs", plan)
        self.assertIn("payment", plan)
        self.assertIn("supabase_rls", plan)
        self.assertIn("supabase_rpc", plan)
        self.assertIn("supabase_storage", plan)
        self.assertIn("backend_scan", recon.results["scan_metadata"]["smart_skip_reasons"])

    def test_cors_openapi_server_leaks_included_in_plan(self):
        recon = NexusREC("https://api.example.com")
        recon.results = {
            "scan_metadata": {},
            "detected_stack": [],
            "basic": {
                "technologies": {},
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Server": "Apache/2.4.41",
                    "Server-Timing": 'dc;desc="aws-fra", cg;desc="global-production"',
                },
                "_html": '<html><script src="swagger-ui-bundle.js"></script></html>',
                "waf": ["None Detected"],
            },
        }
        plan = recon._build_smart_plan(allow_prompts=False)
        self.assertIn("cors", plan)
        self.assertIn("server_leaks", plan)
        # openapi should be triggered because 'swagger' is in html

    def test_openapi_not_included_without_signal(self):
        recon = NexusREC("https://plain.example.com")
        recon.results = {
            "scan_metadata": {},
            "detected_stack": [],
            "basic": {
                "technologies": {},
                "headers": {},
                "_html": "<html>no api docs here</html>",
                "waf": ["None Detected"],
            },
        }
        plan = recon._build_smart_plan(allow_prompts=False)
        # openapi should be skipped because no swagger/openapi signal
        skips = recon.results.get("scan_metadata", {}).get("smart_skip_reasons", {})
        self.assertIn("openapi", skips)

    def test_security_block_limits_http_heavy_modules(self):
        recon = NexusREC("https://blocked.example")
        recon.results = {
            "scan_metadata": {},
            "detected_stack": ["Next.js", "React"],
            "basic": {
                "technologies": {"Next.js": "x", "React": "x"},
                "headers": {},
                "_html": '<div id="__next"></div>',
                "waf": ["Vercel"],
                "security_block": "Vercel Security Challenge",
            },
        }
        plan = recon._build_smart_plan(allow_prompts=False)
        self.assertIn("dns", plan)
        self.assertNotIn("js", plan)
        self.assertNotIn("vuln", plan)
        self.assertIn("js", recon.results["scan_metadata"]["smart_skip_reasons"])


class CliSmokeTests(unittest.TestCase):
    def run_cmd(self, *args):
        return subprocess.run(
            [sys.executable, "nexus_rec.py", *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
        )

    def test_help(self):
        result = self.run_cmd("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--check-deps", result.stdout)

    def test_invalid_module_fails_before_scan(self):
        result = self.run_cmd("example.com", "--modules", "nope", "--auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid module", result.stdout)

    def test_dependency_check_command(self):
        result = self.run_cmd("--check-deps")
        self.assertIn("dependencies", result.stdout.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
