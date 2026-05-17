import requests
import json
import re


class SupabaseRPCRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def find_supabase_refs(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text
            csp = r.headers.get('Content-Security-Policy', '')

            refs = re.findall(r'(https?://[a-zA-Z0-9-]+\.supabase\.co)', html + csp)
            if refs:
                ref = refs[0]
                m = re.search(r'https?://([a-zA-Z0-9-]+)\.supabase\.co', ref)
                if m:
                    findings['project_ref'] = m.group(1)
                    findings['rpc_url'] = f'https://{m.group(1)}.supabase.co/rest/v1/rpc/'

            anon_key = re.search(
                r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
                html
            )
            if anon_key:
                findings['anon_key'] = anon_key.group(1)
        except:
            pass
        self.results['project'] = findings
        return findings

    def enumerate_functions(self):
        findings = []
        project_info = self.results.get('project', {})
        rpc_url = project_info.get('rpc_url', '')
        anon_key = project_info.get('anon_key', '')

        if not rpc_url or not anon_key:
            self.results['rpc_functions'] = findings
            return findings

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        common_rpcs = [
            'hello', 'echo', 'version', 'status', 'ping', 'health',
            'get_users', 'get_profiles', 'get_user', 'get_profile',
            'get_current_user', 'get_me', 'me',
            'login', 'signup', 'register', 'authenticate',
            'create_user', 'update_profile', 'delete_user',
            'get_products', 'get_orders', 'get_transactions',
            'search', 'lookup', 'find', 'query',
            'send_email', 'send_notification', 'notify',
            'calculate', 'compute', 'process', 'validate',
            'check_username', 'check_email', 'is_available',
            'get_upload_url', 'generate_presign_url',
            'get_settings', 'get_config', 'get_public_config',
            'list_buckets', 'get_storage_info',
            'get_messages', 'send_message',
            'get_comments', 'get_posts',
            'get_analytics', 'get_stats', 'get_metrics',
            'get_api_keys', 'regenerate_api_key',
            'admin_check', 'is_admin', 'has_role',
            'get_team', 'get_members', 'get_invites',
            'create_checkout', 'get_subscription',
            'stripe_webhook', 'rewardful_convert',
        ]

        for func_name in common_rpcs:
            try:
                url = rpc_url + func_name
                payload = {}
                r = requests.post(url, headers=headers, json=payload, timeout=8)

                result = {
                    'function': func_name,
                    'status': r.status_code,
                    'url': url,
                }

                if r.status_code in [200, 201]:
                    result['exists'] = True
                    try:
                        data = r.json()
                        result['response'] = str(data)[:300]
                    except:
                        result['response'] = r.text[:300]
                elif r.status_code == 404:
                    result['exists'] = False
                    result['error'] = 'Not Found'
                elif r.status_code == 400:
                    result['exists'] = True
                    result['needs_params'] = True
                    try:
                        error_data = r.json()
                        result['error_detail'] = str(error_data)[:200]
                        if 'message' in error_data:
                            result['hint'] = error_data['message']
                    except:
                        result['error_detail'] = r.text[:200]
                elif r.status_code == 401:
                    result['exists'] = True
                    result['error'] = 'Requires authentication'
                elif r.status_code == 406:
                    result['exists'] = False
                    result['error'] = 'Not Acceptable'
                else:
                    result['exists'] = False
                    result['error'] = f'HTTP {r.status_code}'

                findings.append(result)
            except:
                pass

        exposed = [f for f in findings if f.get('exists')]
        self.results['rpc_functions'] = findings
        self.results['rpc_exposed'] = exposed
        return findings

    def run_all(self):
        self.find_supabase_refs()
        self.enumerate_functions()
        return self.results
