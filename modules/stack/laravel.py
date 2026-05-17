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

    def check_api_debug_mode(self):
        """Check debug mode by POSTing to API endpoints with JSON Accept header.
        Laravel with debug=true returns full stack traces on JSON requests."""
        api_routes = [
            ('POST', '/api/create-session', {}),
            ('POST', '/api/create-chat', {}),
            ('GET', '/democlients', {}),
        ]
        findings = []
        for method, path, data in api_routes:
            try:
                h = {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                }
                if method == 'POST':
                    r = requests.post(f"{self.target_url}{path}", headers=h,
                                      json=data, timeout=10,
                                      allow_redirects=False)
                else:
                    r = requests.get(f"{self.target_url}{path}", headers=h,
                                     timeout=10, allow_redirects=False)

                if r.status_code in [419, 500] and ('"exception"' in r.text or '"trace"' in r.text):
                    import re
                    php_files = set(re.findall(r'"[^"]*\.php"', r.text))
                    server_base = any('/home/' in p or '/var/www/' in p for p in php_files)
                    findings.append({
                        'endpoint': f'{method} {path}',
                        'status': r.status_code,
                        'debug_leak': True,
                        'server_path_leaked': server_base,
                        'php_files_found': len(php_files),
                        'size': len(r.content),
                    })
            except:
                pass
        self.results['api_debug_check'] = findings
        return findings

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

    def detect_boost_package(self):
        """Detect Laravel Boost package and its browser-logs endpoint."""
        findings = {'detected': False}
        try:
            # Check for browser-logger-active script in HTML
            r = self._get(self.target_url)
            if r and 'browser-logger-active' in r.text:
                findings['detected'] = True
                findings['package'] = 'Laravel Boost'
                findings['endpoint'] = '/_boost/browser-logs'
                findings['browser_logging'] = True

                # Test endpoint accessibility
                try:
                    test_r = requests.post(
                        f"{self.target_url}/_boost/browser-logs",
                        headers={
                            'User-Agent': 'Mozilla/5.0',
                            'X-Requested-With': 'XMLHttpRequest',
                            'Content-Type': 'application/json',
                        },
                        json={"logs": [{"type": "test", "timestamp": "2026-01-01T00:00:00Z",
                                        "data": ["test"], "url": self.target_url,
                                        "userAgent": "Mozilla/5.0"}]},
                        timeout=8
                    )
                    if test_r.status_code == 200 and test_r.text == '{"status":"logged"}':
                        findings['injectable'] = True
                    elif test_r.status_code == 500:
                        findings['error_leak'] = True
                        findings['error_leak_body'] = test_r.text[:300]
                except:
                    pass

            # Check for InjectBoost middleware in error traces
            if r and 'InjectBoost' in r.text:
                findings['detected'] = True
                findings['middleware'] = 'Laravel\\Boost\\Middleware\\InjectBoost'

        except:
            pass
        self.results['boost_package'] = findings
        return findings

    def detect_imunify360(self):
        """Detect Imunify360 WAF."""
        try:
            r = requests.get(f"{self.target_url}/.env", timeout=8,
                headers={'User-Agent': 'Mozilla/5.0'},
                allow_redirects=False)
            if r.status_code == 403:
                body = r.text
                if 'imunify' in body.lower() or 'Imunify360' in body:
                    self.results['waf'] = self.results.get('waf', []) + ['Imunify360']
                    return True
            # Also check response body for imunify360 messages
            if 'imunify360' in r.text.lower():
                self.results['waf'] = self.results.get('waf', []) + ['Imunify360']
                return True
        except:
            pass
        return False

    def detect_openresty(self):
        """Detect OpenResty reverse proxy."""
        try:
            r = requests.get(f"{self.target_url}/non-existent", timeout=8,
                headers={'User-Agent': 'Mozilla/5.0'})
            server = r.headers.get('Server', '')
            if 'openresty' in server.lower():
                self.results['reverse_proxy'] = 'OpenResty'
                return True
            # Check for 415 Unsupport Media Type from openresty
            r2 = requests.post(f"{self.target_url}/api/test-openresty",
                headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'},
                json={}, timeout=8)
            if r2.status_code == 415 and 'openresty' in r2.text.lower():
                self.results['reverse_proxy'] = 'OpenResty'
                return True
        except:
            pass
        return False

    def detect_server(self):
        """Detect nginx server header and other infrastructure."""
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            server = r.headers.get('Server', '')
            if 'nginx' in server.lower():
                self.results['server'] = 'nginx'
            elif 'apache' in server.lower():
                self.results['server'] = 'apache'
            else:
                self.results['server'] = server or 'unknown'
            xsrf_cookie = any(c.name == 'XSRF-TOKEN' for c in r.cookies)
            if xsrf_cookie:
                self.results['xsrf_token_detected'] = True
                self.results['laravel_detected'] = True
        except:
            pass
        return self.results

    def detect_coolify(self):
        """Detect Coolify deployment platform."""
        findings = {'detected': False}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            set_cookie = r.headers.get('Set-Cookie', '')
            if 'coolify_session' in set_cookie:
                findings['detected'] = True
                findings['indicators'] = findings.get('indicators', [])
                findings['indicators'].append('coolify_session_cookie')
            try:
                health_r = requests.get(
                    f"{self.target_url}/api/v1/health", timeout=8,
                    headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
                if health_r.status_code == 200:
                    try:
                        data = health_r.json()
                        findings['detected'] = True
                        findings['health_data'] = data
                        findings['indicators'] = findings.get('indicators', [])
                        findings['indicators'].append('/api/v1/health endpoint')
                    except:
                        findings['health_status'] = health_r.status_code
            except:
                pass
            for cookie in r.cookies:
                if cookie.name == 'XSRF-TOKEN':
                    findings['xsrf_token_detected'] = True
        except:
            pass
        self.results['coolify'] = findings
        return findings

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
        self.check_api_debug_mode()
        self.detect_boost_package()
        self.detect_imunify360()
        self.detect_openresty()
        self.scan_sensitive_routes()
        self.check_cve_vulnerabilities()
        self.detect_server()
        self.detect_coolify()
        return self.results
