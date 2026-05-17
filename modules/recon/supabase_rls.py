import requests
import json
import re
from urllib.parse import urljoin


class SupabaseRLSRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def detect_supabase_project(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text
            csp = r.headers.get('Content-Security-Policy', '')

            refs = re.findall(r'(https?://[a-zA-Z0-9.-]+\.supabase\.co)', html + csp)
            if refs:
                findings['supabase_refs'] = list(set(refs))
                for ref in refs:
                    m = re.search(r'https?://([a-zA-Z0-9-]+)\.supabase\.co', ref)
                    if m:
                        findings['project_ref'] = m.group(1)
                        findings['rest_url'] = f'https://{m.group(1)}.supabase.co/rest/v1/'
                        findings['auth_url'] = f'https://{m.group(1)}.supabase.co/auth/v1/'
                        findings['storage_url'] = f'https://{m.group(1)}.supabase.co/storage/v1/'
                        break

            anon_key_match = re.search(
                r'supabaseKey["\']\s*:\s*["\'](eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\']',
                html
            )
            if not anon_key_match:
                anon_key_match = re.search(
                    r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
                    html
                )
            if anon_key_match:
                findings['anon_key'] = anon_key_match.group(1)
                findings['anon_key_preview'] = anon_key_match.group(1)[:30] + '...'

            svc_key_match = re.search(
                r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{100,}\.[a-zA-Z0-9_-]+)',
                html
            )
            if svc_key_match:
                if not anon_key_match or svc_key_match.group(1) != anon_key_match.group(1):
                    findings['possible_service_role_key'] = svc_key_match.group(1)[:30] + '...'
                    findings['service_role_warning'] = 'Potential SERVICE_ROLE_KEY detected in client-side code'

        except:
            pass
        self.results['supabase_project'] = findings
        return findings

    def test_rls_policies(self):
        findings = []
        project_info = self.results.get('supabase_project', {})
        rest_url = project_info.get('rest_url', '')
        anon_key = project_info.get('anon_key', '')

        if not rest_url or not anon_key:
            self.results['rls_test'] = findings
            return findings

        common_tables = [
            'users', 'profiles', 'user_profiles', 'accounts',
            'products', 'orders', 'transactions', 'payments',
            'posts', 'comments', 'articles', 'pages',
            'sessions', 'tokens', 'api_keys', 'settings',
            'config', 'roles', 'permissions', 'audit_logs',
            'customers', 'subscriptions', 'invoices', 'plans',
        ]

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        for table in common_tables:
            try:
                url = f'{rest_url}{table}?limit=1'
                r = requests.get(url, headers=headers, timeout=8)
                result = {
                    'table': table,
                    'status': r.status_code,
                    'url': url,
                }
                if r.status_code == 200:
                    try:
                        data = r.json()
                        result['accessible'] = True
                        result['row_count'] = len(data) if isinstance(data, list) else 1
                        result['preview'] = str(data)[:200]
                    except:
                        result['accessible'] = True
                        result['preview'] = r.text[:200]
                elif r.status_code == 401:
                    result['accessible'] = False
                    result['error'] = 'Unauthorized - RLS blocking'
                elif r.status_code == 406:
                    result['accessible'] = False
                    result['error'] = 'Not Acceptable - table may not exist'
                elif r.status_code == 404:
                    result['accessible'] = False
                    result['error'] = 'Not Found - table does not exist'
                else:
                    result['accessible'] = False
                    result['error'] = f'HTTP {r.status_code}'
                findings.append(result)
            except:
                pass

        open_tables = [f for f in findings if f.get('accessible')]
        if open_tables:
            self.results['rls_open_tables'] = open_tables

        self.results['rls_test'] = findings
        return findings

    def test_auth_endpoints(self):
        findings = {}
        project_info = self.results.get('supabase_project', {})
        auth_url = project_info.get('auth_url', '')
        anon_key = project_info.get('anon_key', '')

        if not auth_url or not anon_key:
            self.results['auth_test'] = findings
            return findings

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
            'Content-Type': 'application/json',
        }

        endpoints_to_test = [
            '/admin/users',
            '/user',
            '/users',
            '/settings',
            '/token?grant_type=password',
        ]

        for ep in endpoints_to_test:
            try:
                url = f'{auth_url.rstrip("/")}{ep}'
                r = requests.get(url, headers=headers, timeout=8)
                findings[ep] = {
                    'status': r.status_code,
                    'url': url,
                }
                if r.status_code == 200:
                    try:
                        findings[ep]['data'] = r.json()
                    except:
                        findings[ep]['preview'] = r.text[:200]
            except:
                pass

        self.results['auth_test'] = findings
        return findings

    def run_all(self):
        self.detect_supabase_project()
        self.test_rls_policies()
        self.test_auth_endpoints()
        return self.results
