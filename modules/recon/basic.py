import requests
import socket
import re
import os
from modules.recon.technologies import WappalyzerEngine

BROWSER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'DNT': '1',
}

USER_AGENTS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
]

import random
import time

class BasicRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self._response = None
        self._html = ""
        self._headers = {}
        self._wappalyzer = WappalyzerEngine()
        self._session = requests.Session()
        self._retries = 3
        self.stealth = False
        self.request_delay = 0

    def _get(self, url, **kwargs):
        headers = BROWSER_HEADERS.copy()
        headers['User-Agent'] = random.choice(USER_AGENTS)
        kwargs.setdefault('headers', {}).update(headers)
        kwargs.setdefault('timeout', 15)
        for attempt in range(self._retries):
            try:
                if self.request_delay:
                    time.sleep(self.request_delay)
                r = self._session.get(url, **kwargs)
                if r.status_code not in [429, 503]:
                    return r
                if attempt < self._retries - 1:
                    time.sleep(2 * (attempt + 1))
            except requests.RequestException:
                if attempt == self._retries - 1:
                    raise
                time.sleep(2)
        return self._session.get(url, **kwargs)

    def check_headers(self):
        try:
            r = self._get(self.target_url, allow_redirects=True)
            self._response = r
            self._html = r.text
            self._headers = r.headers
            h = r.headers
            set_cookie_val = h.get('Set-Cookie', 'MISSING')
            infra_notes = []
            if 'NSC_' in str(set_cookie_val):
                infra_notes.append('NetScaler/ADC (NSC_ cookie)')
            self.results['headers'] = {
                'Server': h.get('Server', 'Unknown'),
                'Content-Type': h.get('Content-Type', 'Unknown'),
                'Content-Security-Policy': h.get('Content-Security-Policy', 'MISSING'),
                'Strict-Transport-Security': h.get('Strict-Transport-Security', 'MISSING'),
                'X-Frame-Options': h.get('X-Frame-Options', 'MISSING'),
                'X-Content-Type-Options': h.get('X-Content-Type-Options', 'MISSING'),
                'X-XSS-Protection': h.get('X-XSS-Protection', 'MISSING'),
                'Referrer-Policy': h.get('Referrer-Policy', 'MISSING'),
                'Permissions-Policy': h.get('Permissions-Policy', 'MISSING'),
                'Set-Cookie': set_cookie_val,
                'Access-Control-Allow-Origin': h.get('Access-Control-Allow-Origin', 'MISSING'),
                'Access-Control-Allow-Methods': h.get('Access-Control-Allow-Methods', 'MISSING'),
                'Access-Control-Allow-Headers': h.get('Access-Control-Allow-Headers', 'MISSING'),
                'Server-Timing': h.get('Server-Timing', 'MISSING'),
                'X-Via-NSCOPI': h.get('X-Via-NSCOPI', 'MISSING'),
                'infra_notes': infra_notes,
                '_raw_headers': dict(h),
            }
            self.results['status_code'] = r.status_code
            self.results['response_time'] = round(r.elapsed.total_seconds(), 3)
            self.results['content_length'] = len(r.content)
            self.results['_html'] = r.text
        except requests.RequestException as e:
            self.results['error'] = str(e)
        return self.results

    def detect_waf(self):
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare-'],
            'CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop', 'cloudfront'],
            'Akamai': ['akamai', 'akamaighost'],
            'AWS WAF': ['awswaf', 'x-amzn-requestid'],
            'F5 BIG-IP': ['big-ip', 'x-f5'],
            'Imperva': ['incapsula', 'imperva'],
            'Sucuri': ['sucuri', 'cloudproxy'],
            'Wordfence': ['wordfence'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Fastly': ['x-fastly', 'fastly-backend'],
            'Vercel Security': ['x-vercel-mitigated', 'vercel security checkpoint', '__vercel_original_path'],
        }
        detected = []
        try:
            r = self._response or self._get(self.target_url, timeout=10)
            if not self._response:
                self._response = r
                self._html = r.text
                self._headers = r.headers
            headers_str = str(r.headers).lower()
            body_lower = r.text.lower()[:5000]
            for waf_name, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig.lower() in headers_str or sig.lower() in body_lower:
                        detected.append(waf_name)
                        break
            self.results['waf'] = list(set(detected)) if detected else ['None Detected']
        except:
            self.results['waf'] = ['Unknown']
        return self.results

    def detect_technologies(self):
        detected = {}
        wapp_results = {}
        try:
            r = self._response or self._get(self.target_url, timeout=15)
            body = r.text
            headers = dict(r.headers)
            cookies = {}
            for k, v in r.cookies.items():
                cookies[k.lower()] = v
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body)
            meta_tags = {}
            for name, content in re.findall(r'<meta\s+[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']', body, re.IGNORECASE):
                meta_tags[name.lower()] = content
            for content, name in re.findall(r'<meta\s+[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE):
                meta_tags[name.lower()] = content

            wapp_results = self._wappalyzer.detect(
                url=self.target_url,
                html=body,
                headers=headers,
                scripts=scripts,
                meta_tags=meta_tags,
                cookies=cookies
            )

            for tech_name, info in wapp_results.items():
                if info.get('implied'):
                    detected[tech_name] = 'Implied'
                else:
                    match_sources = info.get('matches', [])
                    source = match_sources[0] if match_sources else 'Unknown'
                    detected[tech_name] = source

            # Manual overrides for frameworks Wappalyzer may miss
            body_lower = body.lower()
            if '/static/js/main.' in body_lower or re.search(r'id=["\']root["\']', body, re.IGNORECASE):
                if 'React' not in detected:
                    detected['React'] = 'html:(root div or main.js bundle)'
            if re.search(r'/_next/static/', body_lower) or '__NEXT_DATA__' in body:
                if 'Next.js' not in detected:
                    detected['Next.js'] = 'html:__NEXT_DATA__ or _next/static'
            if re.search(r'/static/css/main\.', body_lower):
                if 'Webpack' not in detected and 'Create React App' not in detected:
                    detected['Webpack'] = 'html:/static/css/main.*.css'
            if 'vue' in body_lower and re.search(r'id=["\']app["\']', body, re.IGNORECASE):
                if 'Vue.js' not in detected:
                    detected['Vue.js'] = 'html:vue+app div'

            self.results['technologies'] = detected
            self.results['tech_count'] = len(detected)
            self.results['tech_details'] = {
                k: {
                    'categories': [self._wappalyzer.get_category_name(c) for c in v.get('categories', [])] if k in wapp_results else ['Manual Detection'],
                    'confidence': v.get('confidence', 0) if k in wapp_results else 80,
                }
                for k, v in wapp_results.items() if k in wapp_results
            }
            for k in detected:
                if k not in self.results['tech_details']:
                    self.results['tech_details'][k] = {'categories': ['JavaScript frameworks'], 'confidence': 80}
        except:
            self.results['technologies'] = {}
        return self.results

    def detect_platform_stack(self):
        stack = []
        html_lower = (self._html or '').lower()
        headers_str = str(self._headers).lower()
        header_keys = ' '.join(h.lower() for h in self._headers.keys())

        detections = {
            'Enketo Express': ['enketo express', 'enketo', 'enketo_'],
            'KoboToolbox': ['kobotoolbox', 'kobo ', 'kobo.'],
            'OpenRosa/ODK': ['openrosa', 'odk collect', 'x-openrosa'],
            'Supabase': ['supabase.co', 'supabase'],
            'Next.js': ['__next_data__', '_next/static', 'x-nextjs', 'next.js'],
            'Laravel': ['laravel', 'csrf-token', 'livewire', 'x-laravel'],
            'Inertia.js': ['x-inertia', 'inertia="', 'inertia'],
            'WordPress': ['wp-content', 'wp-json', 'wordpress'],
            'Drupal': ['drupal.settings', 'sites/default'],
            'Shopify': ['shopify', 'myshopify'],
            'GraphQL': ['__typename', 'graphql', 'graphiql'],
            'React': ['react', 'data-reactroot'],
            'Vue.js': ['vue.js', 'vue@', '__vue__'],
            'Nuxt.js': ['_nuxt/', '__nuxt__'],
            'Angular': ['ng-version', 'angular'],
            'Svelte': ['__sveltekit__', 'svelte-'],
            'Django': ['csrftoken', '__django'],
            'Flask': ['flask'],
            'Node.js/Express': ['node.js', 'express'],
            'ASP.NET': ['.net', 'asp.net', 'x-aspnet'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Tailwind CSS': ['tailwindcss', 'cdn.tailwindcss.com'],
            'Joomla': ['joomla'],
            'Magento': ['magento'],
            'Ghost': ['ghost'],
            'WooCommerce': ['woocommerce'],
        }

        for platform, sigs in detections.items():
            for sig in sigs:
                if sig in html_lower or sig in headers_str or sig in header_keys:
                    if platform not in stack:
                        stack.append(platform)
                    break

        if 'x-inertia' in headers_str or 'inertia="' in html_lower:
            if 'Laravel' not in stack:
                stack.append('Laravel')
        if 'GraphQL' in stack and 'Nuxt.js' in stack:
            stack.append('Nuxt.js/GraphQL')

        self.results['detected_stack'] = stack
        return stack

    def get_dns(self):
        try:
            ip = socket.gethostbyname(self.domain)
            self.results['ip'] = ip
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                self.results['reverse_dns'] = hostname
            except:
                self.results['reverse_dns'] = 'N/A'
        except:
            self.results['ip'] = 'Unknown'
            self.results['reverse_dns'] = 'N/A'
        return self.results

    def extract_infra_data(self):
        findings = {}
        try:
            html = self._html or ''
            machines = re.findall(r'data-machine=["\']([^"\']+)["\']', html)
            if machines:
                findings['internal_machine_names'] = list(set(machines))
            data_attrs = re.findall(r'(data-(?:server|host|node|env|app))=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if data_attrs:
                findings['infra_data_attrs'] = list(set(data_attrs))
            # cfemail decode
            cf_email = re.search(r'data-cfemail=["\']([a-f0-9]+)["\']', html)
            if cf_email:
                encoded = cf_email.group(1)
                key = int(encoded[:2], 16)
                decoded = ''.join(chr(int(encoded[i:i+2], 16) ^ key) for i in range(2, len(encoded), 2))
                findings['cfemail_decoded'] = decoded
            # Server-Timing parse
            st = self._headers.get('Server-Timing', '')
            if st:
                parsing = {}
                for part in st.split(','):
                    part = part.strip()
                    m = re.match(r'(\w+);desc="?([^"]*)"?', part)
                    if m:
                        parsing[m.group(1)] = m.group(2)
                    else:
                        m2 = re.match(r'(\w+);dur=([\d.]+)', part)
                        if m2:
                            parsing[m2.group(1)] = f"{m2.group(2)}ms"
                if parsing:
                    findings['server_timing'] = parsing
            # CORS detailed analysis
            acao = self._headers.get('Access-Control-Allow-Origin', '')
            acm = self._headers.get('Access-Control-Allow-Methods', '')
            ach = self._headers.get('Access-Control-Allow-Headers', '')
            acc = self._headers.get('Access-Control-Allow-Credentials', '')
            if acao == '*':
                if acc and acc.lower() == 'true':
                    findings['cors_wildcard'] = True
                    findings['cors_warning'] = ('Wildcard CORS with credentials=true — '
                        'potential data leak. Methods: ' + (acm if acm else 'none'))
                else:
                    findings['cors_wildcard'] = True
                    has_dangerous = any(m in (acm or '').upper() for m in ['PUT', 'POST', 'PATCH', 'DELETE'])
                    if has_dangerous:
                        findings['cors_warning'] = ('Wildcard CORS with write methods: ' + acm)
                    else:
                        findings['cors_warning'] = ('CORS wildcard detected (no credentials, '
                            + ('methods: ' + acm if acm else 'static content only') + ') — low risk')
            self.results['infra_findings'] = findings
        except:
            pass
        return findings

    def jquery_vuln_check(self):
        warnings = []
        try:
            html = self._html or ''
            html_lower = html.lower()
            jq_versions = re.findall(r'jquery[-/.]([0-9]+\.[0-9]+\.[0-9]+)', html_lower)
            jq_versions += re.findall(r'jquery v?([0-9]+\.[0-9]+\.[0-9]+)', html_lower)
            for ver in set(jq_versions):
                parts = [int(x) for x in ver.split('.')]
                if (parts[0] == 1 and parts[1] < 12) or (parts[0] == 1 and parts[1] == 12 and parts[2] < 4):
                    warnings.append({
                        'library': 'jQuery',
                        'version': ver,
                        'vulnerable': True,
                        'note': f'jQuery {ver} has known CVEs (XSS via .html(), prototype pollution). Upgrade to 3.5+'
                    })
                if parts[0] == 1 and parts[1] == 11:
                    warnings.append({
                        'library': 'jQuery',
                        'version': ver,
                        'vulnerable': True,
                        'cve_list': ['CVE-2015-9251', 'CVE-2020-11023'],
                        'note': f'jQuery {ver} is 12+ years old. Multiple XSS vulnerabilities.'
                    })
        except:
            pass
        if warnings:
            self.results['jquery_warnings'] = warnings
        return warnings

    def is_valid_response(self, r):
        cl = len(r.content)
        if cl < 100:
            return False
        body = r.text.lower()
        invalid_patterns = ['cloudflare', 'attention required', 'just a moment', 'enable javascript',
                            '403 forbidden', 'access denied', 'blocked', 'captcha',
                            'please wait while your request is being verified',
                            'vercel security checkpoint', 'challenge-platform',
                            'permission denied', 'request blocked']
        for p in invalid_patterns:
            if p in body:
                return False
        return True

    def check_security_block(self):
        body = self._html or (self._response.text if self._response else '')
        if not body:
            return None
        body_lower = body.lower()
        if 'vercel security checkpoint' in body_lower or 'x-vercel-mitigated' in str(self._headers).lower():
            return 'Vercel Security Challenge (403)'
        if 'x-vercel-mitigated' in str(self._headers).lower():
            return 'Vercel Security Challenge'
        if 'cf-challenge' in body_lower or 'cf-browser-verification' in body_lower:
            return 'Cloudflare Challenge'
        if 'just a moment' in body_lower and 'enable javascript' in body_lower:
            return 'Cloudflare JS Challenge'
        if 'attention required' in body_lower or 'cloudflare' in body_lower:
            return 'Cloudflare Attention Required'
        status = self._response.status_code if self._response else 0
        if status == 403 and len(body) > 1000:
            return f'WAF/Block Page (403, {len(body)} bytes)'
        if status in [403, 429] and len(body) < 100:
            return f'Blocked ({status})'
        return None

    def run_all(self):
        self.check_headers()
        self.detect_waf()
        self.results['security_block'] = self.check_security_block()
        self.detect_technologies()
        self.get_dns()
        self.extract_infra_data()
        self.jquery_vuln_check()
        self.detect_platform_stack()
        return self.results
