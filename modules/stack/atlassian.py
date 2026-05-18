import re
import json
import random
import requests
import time
from urllib.parse import urljoin

USER_AGENTS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
]

JIRA_ENDPOINTS = [
    '/rest/api/2/serverInfo',
    '/rest/api/2/project',
    '/rest/api/2/dashboard',
    '/rest/api/2/attachment/meta',
    '/rest/api/2/groups/picker',
    '/rest/api/2/status',
    '/rest/api/2/resolution',
    '/rest/api/2/issuetype',
    '/rest/api/2/priority',
    '/rest/api/2/configuration',
    '/secure/Dashboard.jspa',
    '/login.jsp',
]

CONFLUENCE_ENDPOINTS = [
    '/rest/api/space',
    '/rest/api/content',
    '/dashboard',
    '/login.action',
]

BITBUCKET_ENDPOINTS = [
    '/rest/api/1.0/projects',
    '/rest/api/1.0/repos',
]

SAML_PATTERNS = [
    r'SAMLRequest',
    r'AuthnRequest',
    r'logonvalidation',
    r'AssertionConsumerService',
    r'SAMLResponse',
]

AZURE_PROXY_HEADERS = [
    'x-ms-proxy-app-id',
    'x-ms-proxy-group-id',
    'x-ms-proxy-subscription-id',
    'x-ms-proxy-service-name',
    'x-ms-proxy-data-center',
    'x-ms-proxy-connector-id',
]

ATLASSIAN_PRODUCTS = {
    'JIRA': ['Atlassian Jira', 'JIRA', 'jira'],
    'Confluence': ['Confluence', 'confluence'],
    'Bitbucket': ['Bitbucket', 'bitbucket'],
    'Crowd': ['Crowd', 'crowd'],
}


class AtlassianRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.results = {}
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    def set_initial_response(self, html, headers):
        self._initial_html = html
        self._initial_headers = headers

    def _get(self, url, **kwargs):
        kwargs.setdefault('headers', {}).update({'User-Agent': random.choice(USER_AGENTS)})
        kwargs.setdefault('timeout', 12)
        for attempt in range(2):
            try:
                r = self._session.get(url, **kwargs)
                if r.status_code not in [429]:
                    return r
                if attempt < 1:
                    time.sleep(2)
            except requests.RequestException:
                if attempt == 1:
                    raise
                time.sleep(2)
        return self._session.get(url, **kwargs)

    def detect_jira(self):
        findings = {}
        base = self.target_url
        for path in JIRA_ENDPOINTS:
            try:
                r = self._get(f"{base}{path}", allow_redirects=False, timeout=8)
                pref = path.replace('/rest/api/2/', '').replace('/secure/', '').replace('/', '_')
                key = f"endpoint_{pref}"
                data = {}
                data['status'] = r.status_code
                data['content_type'] = r.headers.get('Content-Type', '')
                data['length'] = len(r.content)
                data['redirect'] = r.headers.get('Location', '') if r.status_code in (301, 302, 307, 308) else ''

                if path == '/rest/api/2/serverInfo' and r.status_code == 200:
                    try:
                        server_info = r.json()
                        data['version'] = server_info.get('version')
                        data['deployment'] = server_info.get('deploymentType')
                        data['build'] = server_info.get('buildNumber')
                        data['build_date'] = server_info.get('buildDate')
                        data['scm'] = server_info.get('scmInfo', '')[:40]
                        data['server_title'] = server_info.get('serverTitle')
                    except Exception:
                        pass

                if path == '/secure/Dashboard.jspa' and r.status_code == 200:
                    html = r.text
                    x_user = r.headers.get('X-AUSERNAME', '')
                    if x_user:
                        data['x_username'] = x_user
                    proj_link = re.search(r'pid=(\d+)', html)
                    if proj_link:
                        data['leaked_project_id'] = proj_link.group(1)
                    conf_links = re.findall(r'https?://confluence[^"\' ]+', html)
                    if conf_links:
                        data['confluence_urls'] = list(set(conf_links))[:5]
                    intro = re.search(r'Welcome to the.*?JIRA.*?</div>', html, re.DOTALL)
                    if intro:
                        data['internal_message'] = re.sub(r'<[^>]+>', '', intro.group(0))[:300]

                if path == '/rest/api/2/project' and r.status_code == 200:
                    try:
                        projects = r.json()
                        data['project_count'] = len(projects)
                        if projects:
                            data['projects'] = [{'key': p.get('key'), 'name': p.get('name')} for p in projects[:20]]
                    except Exception:
                        pass

                if path == '/login.jsp' and r.status_code == 200:
                    meta_version = re.search(r'data-version="([^"]+)"', r.text)
                    if meta_version:
                        data['meta_version'] = meta_version.group(1)

                azure_headers = {}
                for h in AZURE_PROXY_HEADERS:
                    val = r.headers.get(h, '')
                    if val:
                        azure_headers[h] = val
                if azure_headers:
                    data['azure_app_proxy'] = azure_headers

                findings[path] = data
            except Exception:
                findings[path] = {'status': 'error'}
                continue
        self.results['jira'] = findings
        jira_detected = any(
            v.get('status') in (200, 302, 401)
            for v in findings.values()
        )
        if jira_detected:
            self.results['detected'] = True
            self.results['product'] = 'Jira'
        return findings

    def detect_confluence(self):
        findings = {}
        base = self.target_url.replace('jira', 'confluence')
        if 'confluence' not in base:
            base = base.replace(self.target_url.rstrip('/').rsplit('.', 2)[0] if '.' in self.target_url else '', '')
            base = f"https://confluence.{'.'.join(self.target_url.split('://')[1].split('.')[1:])}" if '.' in self.target_url else self.target_url

        for path in CONFLUENCE_ENDPOINTS:
            try:
                url = f"{self.target_url.replace('jira', 'confluence')}{path}"
                r = self._get(url, allow_redirects=False, timeout=8)
                data = {
                    'status': r.status_code,
                    'redirect': r.headers.get('Location', ''),
                }
                azure_headers = {}
                for h in AZURE_PROXY_HEADERS:
                    val = r.headers.get(h, '')
                    if val:
                        azure_headers[h] = val
                if azure_headers:
                    data['azure_app_proxy'] = azure_headers
                if r.status_code == 200:
                    if 'Confluence' in r.text or 'confluence' in r.text.lower():
                        data['detected'] = True
                    meta_ver = re.search(r'confluence\.version["\': ]+["\']?([^"\' ]+)', r.text)
                    if meta_ver:
                        data['version'] = meta_ver.group(1)
                findings[path] = data
            except Exception:
                findings[path] = {'status': 'error'}
                continue
        self.results['confluence'] = findings
        return findings

    def detect_bitbucket(self):
        findings = {}
        base = self.target_url.replace('jira', 'bitbucket')
        for path in BITBUCKET_ENDPOINTS:
            try:
                r = self._get(f"{base}{path}", allow_redirects=False, timeout=8)
                data = {'status': r.status_code}
                if r.status_code == 200:
                    try:
                        data['data'] = str(r.json())[:200]
                    except Exception:
                        pass
                findings[path] = data
            except Exception:
                findings[path] = {'status': 'error'}
                continue
        self.results['bitbucket'] = findings
        return findings

    def check_azure_app_proxy(self):
        findings = {}
        for path in ['/', '/login', '/dashboard', '/status']:
            try:
                r = self._get(f"{self.target_url}{path}", allow_redirects=False, timeout=8)
                proxy_headers = {}
                for h in AZURE_PROXY_HEADERS:
                    val = r.headers.get(h, '')
                    if val:
                        proxy_headers[h] = val[len(h)+1:] if val.startswith(h+':') else val
                if proxy_headers:
                    tenant = r.headers.get('x-ms-proxy-subscription-id', '')
                    findings['detected'] = True
                    findings['tenant_id'] = tenant
                    findings['service_name'] = r.headers.get('x-ms-proxy-service-name', '')
                    findings['data_center'] = r.headers.get('x-ms-proxy-data-center', '')
                    findings['path'] = path
                    findings['status'] = r.status_code
                    break
            except Exception:
                continue
        self.results['azure_app_proxy'] = findings
        return findings

    def detect_saml_sso(self):
        findings = {}
        saml_paths = ['/', '/login', '/login.ashx', '/saml/login', '/auth/saml']
        for path in saml_paths:
            try:
                r = self._get(f"{self.target_url}{path}", allow_redirects=False, timeout=8)
                text = r.text if hasattr(r, 'text') else ''
                for pattern in SAML_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        findings.setdefault('detected_at', []).append(path)
                        findings['saml_request_found'] = True
                        saml_action = re.search(r'action=["\']([^"\']+AuthnRequest[^"\']*)["\']', text)
                        if saml_action:
                            findings['saml_endpoint'] = saml_action.group(1)
                        meta_state = re.search(r'env=(\w+)', text)
                        if meta_state:
                            findings['environment'] = meta_state.group(1)
                        meta_service = re.search(r'service=(\w+)', text)
                        if meta_service:
                            findings['service'] = meta_service.group(1)
            except Exception:
                continue
        self.results['saml_sso'] = findings
        return findings

    def analyze_anonymous_access(self):
        anon = {}
        jira_data = self.results.get('jira', {})
        for endpoint, data in jira_data.items():
            status = data.get('status')
            if isinstance(status, int) and status in (200, 302) and '401' not in str(data.get('data', '')):
                key = endpoint.split('/')[-1] if '/' in endpoint else endpoint
                anon[key] = {
                    'accessible': True,
                    'status': status,
                    'data': data.get('version') or data.get('leaked_project_id') or data.get('internal_message', '')[:100],
                }
        self.results['anonymous_access'] = anon
        return anon

    def run_all(self):
        self.detect_jira()
        self.check_azure_app_proxy()
        self.detect_saml_sso()
        self.analyze_anonymous_access()
        return self.results
