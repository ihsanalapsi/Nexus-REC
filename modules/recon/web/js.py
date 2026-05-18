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

class JSRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.results = {}
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

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

    def _get_js_files(self, html):
        patterns = [
            r'src=["\']([^"\']+\.js(?:[?#][^"\']*)?)["\']',
            r'href=["\']([^"\']+\.js(?:[?#][^"\']*)?)["\']',
            r'import\(["\']([^"\']+\.js)["\']\)',
            r'require\(["\']([^"\']+\.js)["\']\)',
            r'url\(["\']([^"\']+\.js)["\']\)',
        ]
        files = []
        for p in patterns:
            files.extend(re.findall(p, html, re.IGNORECASE))
        return list(set(files))

    def audit_libraries(self):
        try:
            r = self._get(self.target_url)
            html = r.text
            libs = []
            patterns = {
                'jQuery': (r'jquery[-/.]([0-9]+\.[0-9]+\.[0-9]+)', r'jQuery v([0-9]+\.[0-9]+\.[0-9]+)'),
                'Bootstrap': (r'bootstrap[-/.]([0-9]+\.[0-9]+\.[0-9]+)', r'Bootstrap v([0-9]+\.[0-9]+\.[0-9]+)'),
                'React': (r'react@([0-9]+\.[0-9]+\.[0-9]+)', r'React v?([0-9]+\.[0-9]+\.[0-9]+)'),
                'Vue.js': (r'vue@([0-9]+\.[0-9]+\.[0-9]+)', r'Vue\.js v?([0-9]+\.[0-9]+\.[0-9]+)'),
                'Angular': (r'angular@([0-9]+\.[0-9]+\.[0-9]+)', r'Angular v?([0-9]+\.[0-9]+\.[0-9]+)'),
                'Next.js': (r'next@([0-9]+\.[0-9]+\.[0-9]+)', r'Next\.js v?([0-9]+\.[0-9]+\.[0-9]+)'),
                'Nuxt.js': (r'nuxt@([0-9]+\.[0-9]+\.[0-9]+)', r'Nuxt\.js v?([0-9]+\.[0-9]+\.[0-9]+)'),
                'Lodash': (r'lodash[-/.]([0-9]+\.[0-9]+\.[0-9]+)',),
                'Moment.js': (r'moment[-/.]([0-9]+\.[0-9]+\.[0-9]+)',),
                'Axios': (r'axios@([0-9]+\.[0-9]+\.[0-9]+)',),
                'Chart.js': (r'chart\.js@?([0-9]+\.[0-9]+\.[0-9]+)',),
                'D3.js': (r'd3@?([0-9]+\.[0-9]+\.[0-9]+)',),
                'GSAP': (r'gsap@?([0-9]+\.[0-9]+\.[0-9]+)',),
                'Three.js': (r'three@?([0-9]+\.[0-9]+\.[0-9]+)',),
                'Socket.IO': (r'socket\.io[-/.]([0-9]+\.[0-9]+\.[0-9]+)',),
                'Swiper': (r'swiper[-/.]([0-9]+\.[0-9]+\.[0-9]+)',),
                'Alpine.js': (r'alpinejs@?([0-9]+\.[0-9]+\.[0-9]+)',),
                'Turbolinks': (r'turbolinks@?([0-9]+\.[0-9]+\.[0-9]+)',),
            }
            for lib_name, pats in patterns.items():
                for pat in pats:
                    m = re.search(pat, html, re.IGNORECASE)
                    if m:
                        libs.append({'name': lib_name, 'version': m.group(1)})
                        break
            self.results['libraries'] = libs
            self.results['total_script_tags'] = len(re.findall(r'<script', html))
            self.results['inline_scripts'] = len(re.findall(r'<script[^>]*>[\s\S]*?</script>', html))
            self.results['module_scripts'] = len(re.findall(r'type=["\']module["\']', html))
            self.results['eval_detected'] = 'eval(' in html.lower()
            self.results['document_write'] = 'document.write(' in html.lower()
        except:
            self.results['libraries'] = []
        return self.results

    def detect_mobile_apps(self, html=None):
        findings = {}
        try:
            if html is None:
                r = self._get(self.target_url)
                html = r.text
            ios = re.search(r'itunes\.apple\.com/app/[^"\']*/id(\d+)', html)
            if ios:
                findings['ios_app_id'] = ios.group(1)
            android = re.search(r'play\.google\.com/store/apps/details\?id=([a-zA-Z0-9._-]+)', html)
            if android:
                findings['android_app_id'] = android.group(1)
            huawei = re.search(r'appgallery\.huawei\.com/#/app/(\w+)', html)
            if huawei:
                findings['huawei_app_id'] = huawei.group(1)
            ua_strings = re.findall(r'["\']([a-zA-Z]+Mobile-[A-Za-z]+)["\']', html)
            if ua_strings:
                findings['app_user_agents'] = list(set(ua_strings))
        except:
            pass
        self.results['mobile_apps'] = findings
        return findings

    def detect_jquery_vulns(self, html=None):
        warnings = []
        try:
            if html is None:
                r = self._get(self.target_url)
                html = r.text
            html_lower = html.lower()
            jq_versions = re.findall(r'jquery[-/.]([0-9]+\.[0-9]+\.[0-9]+)', html_lower)
            jq_versions += re.findall(r'jquery v?([0-9]+\.[0-9]+\.[0-9]+)', html_lower)
            for ver in set(jq_versions):
                parts = [int(x) for x in ver.split('.')]
                if parts[0] == 1 and parts[1] == 11:
                    warnings.append({
                        'library': 'jQuery', 'version': ver, 'vulnerable': True,
                        'cve_list': ['CVE-2015-9251', 'CVE-2020-11023'],
                        'note': f'jQuery {ver} released 2014 — 12+ years old. Multiple XSS vulnerabilities.'
                    })
                elif parts[0] == 1 and parts[1] < 12:
                    warnings.append({
                        'library': 'jQuery', 'version': ver, 'vulnerable': True,
                        'note': f'jQuery {ver} is outdated. Known CVEs.'
                    })
        except:
            pass
        self.results['jquery_vulns'] = warnings
        return warnings

    def extract_apis(self, html=None, max_files=15):
        try:
            if html is None:
                r = self._get(self.target_url)
                html = r.text
            js_files = self._get_js_files(html)
            all_apis = set()
            all_tokens = set()
            all_secrets = set()
            all_emails = set()
            all_internal_ips = set()
            all_mobile_ua = set()

            api_patterns = [
                r'["\']((?:/api|/v1|/v2|/v3|/rest|/graphql|/webhook)[a-zA-Z0-9/_-]*)["\']',
                r'["\'](https?://[^"\']*api[^"\']*)["\']',
                r'["\'](https?://[^"\']*/v\d/[^"\']*)["\']',
                r'fetch\(["\']([^"\']+)["\']\)',
                r'axios\.\w+\(["\']([^"\']+)["\']\)',
                r'\$\.\w+\(["\']([^"\']+)["\']\)',
                r'axios\(\s*["\']([^"\']+)["\']',
                r'request\(\s*["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'["\'](https?://[a-zA-Z0-9.-]+(?:backend|api|api-gateway|server|service|app|admin)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^"\']*)?)["\']',
                r'["\'](https?://[a-zA-Z0-9.-]+\.(?:railway|heroku|render|fly|vercel|netlify|onrender)\.app(?:/[^"\']*)?)["\']',
                r'["\'](https?://[a-zA-Z0-9.-]+\.supabase\.co(?:/[^"\']*)?)["\']',
                r'const\s+\w+\s*=\s*["\'](https?://[^"\']+)["\']',
                r'let\s+\w+\s*=\s*["\'](https?://[^"\']+)["\']',
                r'var\s+\w+\s*=\s*["\'](https?://[^"\']+)["\']',
                # ASP.NET MVC controller/action patterns
                r'["\'](/(?:Lookup|SuggestedSearch|Search|Autocomplete|Query)/[a-zA-Z0-9_-]*)["\']',
                r'["\'](/(?:Get|Post|Put|Delete)[A-Z][a-zA-Z0-9/_-]*)["\']',
            ]

            secret_patterns = [
                (r'["\'][A-Za-z0-9+/=]{40,}["\']', 'base64_token'),
                (r'AIza[0-9A-Za-z_-]{35}', 'google_api_key'),
                (r'SK-[0-9a-fA-F]{32,}', 'openai_key'),
                (r'sk-[0-9a-fA-F]{32,}', 'stripe_key'),
                (r'pk_live_[0-9a-zA-Z]{24,}', 'stripe_pk'),
                (r'sk_live_[0-9a-zA-Z]{24,}', 'stripe_sk'),
                (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
                (r'ghp_[0-9a-zA-Z]{36}', 'github_token'),
                (r'gho_[0-9a-zA-Z]{36}', 'github_oauth'),
                (r'xox[bapr]-[0-9a-zA-Z-]{24,}', 'slack_token'),
            ]
            known_non_secrets = {
                'createDedupedByCallsiteServerErrorLoggerDev',
                'createRenderSearchParamsFromClient',
                'disableSmoothScrollDuringRouteTransition',
                'DEDUPED_BY_CALLSITE_SERVER_ERROR_LOGGER',
                'getSelectedParams',
                'getSelectedSearchParams',
                'isBot',
            }

            email_pattern = r'["\' ]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\' ]'
            ip_pattern = r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'

            for js in js_files[:max_files]:
                js_url = urljoin(self.target_url, js)
                try:
                    js_resp = self._get(js_url, timeout=15)
                    js_content = js_resp.text
                    if not js_content:
                        continue
                    for pat in api_patterns:
                        matches = re.findall(pat, js_content)
                        all_apis.update(matches)
                    for pat, ptype in secret_patterns:
                        matches = re.findall(pat, js_content)
                        for m in matches:
                            val = m if isinstance(m, str) else m[0]
                            clean = val.strip('"\'')
                            if clean in known_non_secrets:
                                continue
                            if ptype == 'base64_token':
                                if len(clean) > 200:
                                    continue
                                if re.match(r'^[a-z]+(?:[A-Z][a-z]*)*\d*$', clean):
                                    continue
                            all_tokens.add((clean[:50], ptype))
                    emails = re.findall(email_pattern, js_content)
                    all_emails.update(emails)
                    ips = re.findall(ip_pattern, js_content)
                    all_internal_ips.update(ips)
                except:
                    pass

            self.results['extracted_apis'] = sorted(all_apis)
            self.results['potential_tokens'] = list(set(t[0] for t in all_tokens))
            self.results['token_types'] = list(set((t[1] for t in all_tokens)))
            self.results['emails_found'] = sorted(all_emails)
            self.results['internal_ips'] = sorted(all_internal_ips)
            self.results['js_files_scanned'] = min(len(js_files), max_files)
            self.results['total_js_files'] = len(js_files)
        except:
            self.results['extracted_apis'] = []
            self.results['potential_tokens'] = []
        return self.results

    def discover_source_maps(self, html=None):
        try:
            if html is None:
                r = self._get(self.target_url)
                html = r.text
            js_files = self._get_js_files(html)
            source_maps = []
            webpack_chunks = set()
            graphql_ops = set()

            for js in js_files[:10]:
                js_url = urljoin(self.target_url, js)
                try:
                    js_content = self._get(js_url, timeout=10).text
                    sm = re.findall(r'sourceMappingURL=([^\s"\']+)', js_content)
                    for s in sm:
                        sm_url = urljoin(js_url, s)
                        source_maps.append({'js_file': js, 'map_url': sm_url})
                    chunks = re.findall(r'webpackChunk\w+', js_content)
                    webpack_chunks.update(chunks)
                    gql = re.findall(r'(query|mutation)\s+\w+\s*\{[^}]+', js_content, re.IGNORECASE)
                    graphql_ops.update(gql)
                except:
                    pass

            self.results['source_maps'] = source_maps
            self.results['webpack_chunks'] = sorted(webpack_chunks)
            self.results['graphql_operations'] = sorted(graphql_ops)
        except:
            self.results['source_maps'] = []
        return self.results

    def extract_amplify_config(self, html=None, max_files=20):
        amplify_config = {}
        try:
            if html is None:
                r = self._get(self.target_url)
                html = r.text
            js_files = self._get_js_files(html)
            all_js_content = ''
            for js in js_files[:max_files]:
                js_url = urljoin(self.target_url, js)
                try:
                    resp = self._get(js_url, timeout=10)
                    all_js_content += resp.text + '\n'
                except:
                    pass

            appsync_patterns = {
                'aws_appsync_graphqlEndpoint': r'aws_appsync_graphqlEndpoint["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_appsync_region': r'aws_appsync_region["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_appsync_authenticationType': r'aws_appsync_authenticationType["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_appsync_apiKey': r'aws_appsync_apiKey["\']*\s*:\s*["\'](da2-[a-zA-Z0-9]+)["\']',
                'aws_project_region': r'aws_project_region["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_user_pools_id': r'aws_user_pools_id["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_user_pools_web_client_id': r'aws_user_pools_web_client_id["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_cognito_identity_pool_id': r'aws_cognito_identity_pool_id["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_user_files_s3_bucket': r'aws_user_files_s3_bucket["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_user_files_s3_bucket_region': r'aws_user_files_s3_bucket_region["\']*\s*:\s*["\']([^"\']+)["\']',
                'oauth_domain': r'oauth["\']*\s*:\s*\{[^}]*domain["\']*\s*:\s*["\']([^"\']+)["\']',
                'user_pool_id': r'user_pool_id["\']*\s*:\s*["\']([^"\']+)["\']',
                'user_pool_client_id': r'user_pool_client_id["\']*\s*:\s*["\']([^"\']+)["\']',
                'identity_pool_id': r'identity_pool_id["\']*\s*:\s*["\']([^"\']+)["\']',
                'bucket_name': r'bucket_name["\']*\s*:\s*["\']([^"\']+)["\']',
                'aws_appsync_graphqlEndpoint_https': r'appsync-api\.([a-z0-9-]+)\.amazonaws\.com/graphql',
                'default_authorization_type': r'default_authorization_type["\']*\s*:\s*["\']([^"\']+)["\']',
            }

            for key, pat in appsync_patterns.items():
                matches = re.findall(pat, all_js_content)
                if matches:
                    amplify_config[key] = list(set(matches))

            if amplify_config:
                self.results['amplify_config'] = amplify_config
        except:
            pass
        return amplify_config

    def run_all(self):
        try:
            r = self._get(self.target_url)
            html = r.text
        except:
            return self.results
        self.audit_libraries()
        self.extract_apis(html)
        self.extract_amplify_config(html)
        self.discover_source_maps(html)
        self.detect_mobile_apps(html)
        self.detect_jquery_vulns(html)
        return self.results
