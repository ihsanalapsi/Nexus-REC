import requests
import re
import json

class LaravelRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.results = {}
        self._session = requests.Session()

    def _get(self, url, **kwargs):
        kwargs.setdefault('headers', {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'})
        kwargs.setdefault('timeout', 10)
        try:
            return self._session.get(url, **kwargs)
        except:
            return None

    def detect_inertia(self):
        try:
            r = self._get(self.target_url)
            if not r:
                return self.results
            html = r.text
            raw_headers = {k.lower(): str(v).lower() for k, v in r.headers.items()}

            inertia_signals = {
                'detected': False,
                'x_inertia_header': 'X-Inertia' in r.headers.get('Vary', '') or 'x-inertia' in raw_headers,
                'inertia_meta': 'inertia' in html and ('inertia="' in html or "inertia='" in html),
                'page_data': False,
                'routes_exposed': False,
                'routes_count': 0,
            }

            if 'x-inertia' in raw_headers.get('vary', '') or inertia_signals['inertia_meta']:
                inertia_signals['detected'] = True

            page_match = re.search(r'&quot;version&quot;:&quot;([^&]+)&quot;', html)
            if page_match:
                inertia_signals['page_data'] = True
                inertia_signals['version'] = page_match.group(1)

            page_match2 = re.search(r'"version":"([^"]+)"', html)
            if page_match2:
                inertia_signals['page_data'] = True
                inertia_signals['version'] = page_match2.group(1)

            self.results['inertia'] = inertia_signals
        except:
            self.results['inertia'] = {'detected': False}
        return self.results

    def extract_routes(self):
        try:
            r = self._get(self.target_url)
            if not r:
                return self.results
            html = r.text

            routes = []
            pattern = r'window\.routes\s*=\s*({.*?});</script>'
            match = re.search(pattern, html, re.DOTALL)
            if match:
                try:
                    raw = match.group(1)
                    raw = re.sub(r'&quot;', '"', raw)
                    data = json.loads(raw)
                    for group, group_routes in data.items():
                        if isinstance(group_routes, list):
                            for route in group_routes:
                                if isinstance(route, dict) and 'uri' in route:
                                    routes.append({
                                        'group': group,
                                        'uri': route.get('uri', ''),
                                        'name': route.get('name', ''),
                                        'params': route.get('parameters', []),
                                    })
                    self.results['routes_exposed'] = bool(routes)
                    self.results['routes'] = routes
                    self.results['route_groups'] = list(set(r.get('group', 'unknown') for r in routes))
                    self.results['routes_by_group'] = {}
                    for r in routes:
                        g = r.get('group', 'unknown')
                        self.results['routes_by_group'].setdefault(g, []).append(r['uri'])
                except json.JSONDecodeError:
                    self.results['routes_exposed'] = False
            else:
                self.results['routes_exposed'] = False
        except:
            self.results['routes_exposed'] = False
        return self.results

    def extract_oauth_ids(self):
        try:
            redirect_endpoints = ['/auth/redirect/google', '/auth/redirect/facebook',
                                  '/auth/redirect/linkedin', '/auth/redirect/apple',
                                  '/auth/redirect/github', '/auth/redirect/twitter']
            oauth_findings = []
            for ep in redirect_endpoints:
                r = self._get(f"{self.target_url}{ep}", allow_redirects=False)
                if r and r.status_code in [302, 301]:
                    location = r.headers.get('Location', '')
                    client_id = re.search(r'client_id=([^&]+)', location)
                    redirect_uri = re.search(r'redirect_uri=([^&]+)', location)
                    if client_id:
                        oauth_findings.append({
                            'endpoint': ep,
                            'provider': ep.split('/')[-1],
                            'client_id': client_id.group(1),
                            'redirect_uri': redirect_uri.group(1) if redirect_uri else '',
                            'full_location': location[:200],
                        })
            self.results['oauth_providers'] = oauth_findings
        except:
            self.results['oauth_providers'] = []
        return self.results

    def analyze_cookies(self):
        try:
            r = self._get(self.target_url)
            if not r:
                return self.results
            cookies_info = {}
            for k, v in r.cookies.items():
                cookies_info[k] = {
                    'value_preview': v[:30],
                    'secure': bool(r.cookies.get(k)),
                }
            set_cookie_headers = r.headers.get_all('Set-Cookie') if hasattr(r.headers, 'get_all') else [r.headers.get('Set-Cookie', '')]
            cookie_parts = []
            for sc in r.headers.get('Set-Cookie', '').split('Set-Cookie:'):
                cookie_parts.extend(sc.strip().split('\n'))

            session_name = None
            for c in r.cookies:
                if 'session' in c.name.lower():
                    session_name = c.name
                    break

            self.results['cookies'] = {
                'count': len(r.cookies),
                'session_name': session_name,
                'cookie_names': list(cookies_info.keys()),
                'has_httponly': any('httponly' in str(c).lower() for c in r.cookies),
                'has_secure': all(c.secure for c in r.cookies) if r.cookies else False,
            }
        except:
            self.results['cookies'] = {}
        return self.results

    def check_debug_mode(self):
        try:
            r = requests.get(f"{self.target_url}/non-existent-path-fast2026-recon", timeout=10)
            indicators = [
                'Whoops!', 'Laravel', 'Ignition', 'Sentry', 'DebugBar',
                'Whoops\\Exception', 'laravel_log', 'stack trace:',
                'SQLSTATE', 'PDOException', 'QueryException',
                '<title>Error</title>', 'APP_KEY=', 'APP_DEBUG=',
                'Symfony\\Component\\Debug\\Exception',
                'dd('
            ]
            found = [i for i in indicators if i.lower() in r.text.lower()]
            self.results['debug_mode'] = len(found) > 0
            self.results['indicators'] = found
            self.results['error_page_size'] = len(r.content)
        except:
            self.results['debug_mode'] = False
        return self.results

    def scan_sensitive_routes(self):
        routes = [
            '/telescope', '/horizon', '/nova', '/nova-api',
            '/_ignition/health-check', '/_ignition/execute-solution',
            '/.env', '/.env.example', '/storage/logs/laravel.log',
            '/storage/logs/', '/vendor', '/vendor/phpunit',
            '/api/user', '/api/users', '/api/auth',
            '/config', '/config/app.php', '/config/database.php',
            '/routes', '/routes/web.php', '/routes/api.php',
            '/artisan', '/phpunit.xml', '/composer.json',
            '/composer.lock', '/package.json', '/yarn.lock',
            '/.git', '/.git/config', '/.git/HEAD',
            '/.gitignore', '/.htaccess', '/server.php',
            '/_debugbar/open', '/debugbar',
        ]
        found = []
        for route in routes:
            try:
                url = f"{self.target_url}{route}"
                r = requests.get(url, timeout=8, allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code in [200, 301, 302, 403, 401]:
                    content_type = r.headers.get('Content-Type', '')
                    found.append({
                        'route': route, 'status': r.status_code,
                        'length': len(r.content),
                        'type': content_type
                    })
            except:
                pass
        self.results['sensitive_routes'] = found
        return found

    def check_cve_vulnerabilities(self):
        vulns = []
        try:
            r = requests.get(f"{self.target_url}/_ignition/health-check", timeout=8)
            if r.status_code in [200, 302]:
                vulns.append({'cve': 'CVE-2021-3129', 'endpoint': '/_ignition/health-check',
                              'status': 'Potential Ignition RCE - Verify manually'})
        except:
            pass
        try:
            r = requests.get(f"{self.target_url}/_ignition/execute-solution", timeout=8)
            if r.status_code not in [404, 405]:
                vulns.append({'cve': 'CVE-2021-3129', 'endpoint': '/_ignition/execute-solution',
                              'status': f'Responded with {r.status_code}'})
        except:
            pass
        try:
            r = requests.get(f"{self.target_url}/nova", timeout=8)
            if r.status_code == 200:
                vulns.append({'cve': 'Nova Exposure', 'endpoint': '/nova',
                              'status': 'Nova admin panel accessible without auth'})
        except:
            pass
        self.results['cve_checks'] = vulns
        return vulns

    def run_all(self):
        self.detect_inertia()
        self.extract_routes()
        self.extract_oauth_ids()
        self.analyze_cookies()
        self.check_debug_mode()
        self.scan_sensitive_routes()
        self.check_cve_vulnerabilities()
        return self.results
