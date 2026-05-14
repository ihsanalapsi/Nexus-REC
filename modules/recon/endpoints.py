import requests
import re
import hashlib
import concurrent.futures
from urllib.parse import urljoin


class EndpointRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self._homepage_html = None
        self._homepage_length = None
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def _fetch_homepage(self):
        if self._homepage_html is not None:
            return
        try:
            r = self._session.get(self.target_url, timeout=10)
            self._homepage_html = r.text
            self._homepage_length = len(r.content)
        except:
            pass

    def _is_spa_catchall(self, r):
        self._fetch_homepage()
        if self._homepage_length is None:
            return False
        if 'text/html' not in r.headers.get('Content-Type', ''):
            return False
        if len(r.content) != self._homepage_length:
            return False
        sig1 = hashlib.md5(r.text[:1000].encode()).hexdigest()
        sig2 = hashlib.md5(self._homepage_html[:1000].encode()).hexdigest()
        if sig1 == sig2:
            return True
        if r.text == self._homepage_html:
            return True
        return False

    def _request(self, url, timeout=5, method='GET', **kwargs):
        kwargs.setdefault('allow_redirects', False)
        kwargs.setdefault('timeout', timeout)
        try:
            return self._session.request(method, url, **kwargs)
        except:
            return None

    def detect_login_forms(self):
        findings = []
        login_paths = [
            '/login', '/signin', '/auth', '/login/', '/auth/login',
            '/user/login', '/users/login', '/account/login',
            '/wp-login.php', '/administrator', '/admin/login',
        ]
        self._fetch_homepage()

        def _check(path):
            url = urljoin(self.target_url, path)
            r = self._request(url, timeout=6)
            if r and r.status_code == 200 and not self._is_spa_catchall(r):
                html = r.text
                has_password = bool(re.search(r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE))
                if has_password:
                    has_csrf = bool(re.search(r'csrf|_token|authenticity_token', html, re.IGNORECASE))
                    title_m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                    return {
                        'path': path, 'status': r.status_code,
                        'size': len(r.content), 'has_password_field': True,
                        'has_csrf': has_csrf,
                        'title': title_m.group(1) if title_m else '',
                    }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for r in ex.map(_check, login_paths):
                if r:
                    findings.append(r)
        self.results['login_forms'] = findings
        return findings

    def test_http_methods(self):
        findings = []
        self._fetch_homepage()
        targets = [
            '/api/', '/api/v1/', '/api/v2/',
            '/graphql', '/submission', '/upload',
            '/login', '/logout', '/formList', '/manifest',
            '/admin', '/backup', '/config',
        ]
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']

        def _check_path(path):
            url = urljoin(self.target_url, path)
            path_findings = []
            get_response_obj = None
            for method in methods:
                r = self._request(url, timeout=4, method=method)
                if r and (r.status_code not in [404, 405] or r.status_code == 405):
                    if method == 'GET':
                        get_response_obj = r
                    path_findings.append({
                        'method': method,
                        'status': r.status_code,
                        'size': len(r.content),
                        'content_type': r.headers.get('Content-Type', ''),
                    })
            if path_findings:
                allowed = [m['method'] for m in path_findings if m['status'] not in [404, 405]]
                if allowed:
                    is_spa = False
                    if get_response_obj and path != '/':
                        is_spa = self._is_spa_catchall(get_response_obj)
                    non_get = [m for m in allowed if m in ['POST', 'PUT', 'PATCH', 'DELETE']]
                    return {
                        'path': path,
                        'methods': path_findings,
                        'allowed_methods': allowed,
                        'interesting': bool(non_get) and not is_spa,
                        'non_get_methods': non_get,
                        'is_spa_catchall': is_spa,
                    }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futures = [ex.submit(_check_path, p) for p in targets]
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    findings.append(r)
        findings.sort(key=lambda x: x['path'])
        self.results['http_methods'] = findings
        return findings

    def check_api_redirects(self):
        findings = []
        api_paths = ['/api/', '/api/v1', '/api/v2', '/v1', '/v2', '/swagger', '/api-docs']

        def _check(path):
            url = urljoin(self.target_url, path)
            r = self._request(url, timeout=6)
            if r and r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get('Location', '')
                scheme = 'HTTPS' if location.startswith('https') else 'HTTP' if location.startswith('http') else 'RELATIVE'
                is_external = self.domain not in location if location.startswith('http') else False
                return {
                    'path': path, 'status': r.status_code,
                    'redirect_to': location[:120],
                    'scheme': scheme, 'is_external': is_external,
                    'warn_http': scheme == 'HTTP',
                }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
            for r in ex.map(_check, api_paths):
                if r:
                    findings.append(r)
        self.results['api_redirects'] = findings
        return findings

    def detect_platform_endpoints(self):
        findings = {}
        self._fetch_homepage()
        html = self._homepage_html or ''
        html_lower = html.lower()

        platform_checks = {
            'Enketo/ODK': {
                'endpoints': ['/formList', '/submission', '/manifest',
                              '/upload', '/downloadForm', '/instanceList',
                              '/instance', '/media'],
                'detected': any(sig in html_lower for sig in ['enketo', 'kobotoolbox', 'openrosa']),
            },
            'WordPress': {
                'endpoints': ['/wp-admin', '/wp-content', '/wp-json',
                              '/wp-login.php', '/xmlrpc.php'],
                'detected': any(sig in html_lower for sig in ['wp-content', 'wp-json']),
            },
            'Laravel': {
                'endpoints': ['/_debugbar', '/telescope', '/horizon',
                              '/nova', '/vendor', '/artisan'],
                'detected': 'laravel' in html_lower or 'csrf-token' in html_lower or 'livewire' in html_lower,
            },
            'Next.js': {
                'endpoints': ['/_next/static', '/__nextjs', '/api/health'],
                'detected': '__next_data__' in html_lower or '_next/static' in html_lower,
            },
            'Drupal': {
                'endpoints': ['/user/login', '/node', '/sites/default'],
                'detected': 'drupal.settings' in html_lower,
            },
            'Supabase': {
                'endpoints': ['/rest/v1', '/auth/v1', '/storage/v1'],
                'detected': 'supabase' in html_lower,
            },
            'GraphQL': {
                'endpoints': ['/graphql', '/graphiql', '/playground',
                              '/v1/graphql', '/api/graphql'],
                'detected': 'graphql' in html_lower or '__typename' in html_lower,
            },
        }

        def _check_platform(platform, info):
            plat_findings = []
            for ep in info['endpoints']:
                url = urljoin(self.target_url, ep)
                r = self._request(url, timeout=5)
                if r and r.status_code not in [404] and not self._is_spa_catchall(r):
                    plat_findings.append({
                        'path': ep, 'status': r.status_code,
                        'size': len(r.content),
                    })
            if plat_findings or info['detected']:
                return (platform, {
                    'detected': info['detected'],
                    'endpoints_found': plat_findings,
                    'endpoint_count': len(plat_findings),
                })
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(_check_platform, p, i): p for p, i in platform_checks.items()}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    findings[r[0]] = r[1]

        or_findings = {}
        for ep in ['/formList', '/submission', '/manifest']:
            url = urljoin(self.target_url, ep)
            r_std = self._request(url, timeout=5)
            r_odk = self._request(url, timeout=5, headers={'X-OpenRosa-Version': '1.0'})
            if r_std and r_odk:
                if r_std.status_code != r_odk.status_code or (r_odk.status_code not in [404] and not self._is_spa_catchall(r_odk)):
                    or_findings[ep] = {
                        'standard_status': r_std.status_code,
                        'openrosa_status': r_odk.status_code,
                        'different_response': r_std.status_code != r_odk.status_code,
                    }
        if or_findings:
            findings['OpenRosa'] = or_findings

        self.results['platform_endpoints'] = findings
        return findings

    def check_open_login_registration(self):
        findings = {}
        self._fetch_homepage()
        paths = {
            'register': ['/register', '/signup', '/create-account',
                         '/account/register', '/users/register'],
            'password_reset': ['/forgot-password', '/reset-password',
                               '/password/reset', '/forgot'],
            'profile': ['/profile', '/account', '/dashboard', '/me'],
        }

        def _check_path(category, path):
            url = urljoin(self.target_url, path)
            r = self._request(url, timeout=5)
            if r and r.status_code == 200 and not self._is_spa_catchall(r):
                return (category, {
                    'path': path, 'status': r.status_code,
                    'size': len(r.content),
                })
            return None

        all_tasks = [(cat, p) for cat, plist in paths.items() for p in plist]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(_check_path, c, p): c for c, p in all_tasks}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    cat, entry = r
                    findings.setdefault(cat, []).append(entry)
        self.results['open_endpoints'] = findings
        return findings

    def run_all(self):
        self.detect_login_forms()
        self.test_http_methods()
        self.check_api_redirects()
        self.detect_platform_endpoints()
        self.check_open_login_registration()
        return self.results
