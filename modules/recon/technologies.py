import json
import re
import os

def _compile_patterns(patterns):
    if isinstance(patterns, str):
        return [re.compile(patterns, re.IGNORECASE)]
    if isinstance(patterns, list):
        return [re.compile(p, re.IGNORECASE) if isinstance(p, str) else p for p in patterns]
    return []

class WappalyzerEngine:
    def __init__(self):
        self.technologies = {}
        self.categories = {}
        self._load()

    # Categories for techs NOT in Wappalyzer DB (our custom fallbacks)
    FALLBACK_CATEGORIES = {
        'Lucide': [17],      # Font scripts
        'Turbopack': [47],   # Development
    }

    def _load(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, 'data', 'technologies.json')
        with open(path, 'r', encoding='utf-8') as f:
            self.technologies = json.load(f)
        cat_path = os.path.join(base, 'data', 'categories.json')
        if os.path.exists(cat_path):
            with open(cat_path, 'r') as f:
                self.categories = json.load(f)

    BLOCK_PAGE_MARKERS = [
        'vercel security checkpoint', 'attention required', 'just a moment',
        'enable javascript', '403 forbidden', 'access denied',
        'please wait while your request is being verified',
        'challenge-platform', 'permission denied', 'request blocked',
    ]

    def _match_any(self, patterns, text):
        if not text:
            return False
        compiled = _compile_patterns(patterns)
        for cp in compiled:
            if cp.search(text):
                return True
        return False

    def _is_security_block(self, html):
        if not html:
            return False
        html_lower = html.lower()
        return any(marker in html_lower for marker in self.BLOCK_PAGE_MARKERS)

    HTML_FALLBACKS = {
        'Next.js': [
            r'_next/static/',
            r'__NEXT_DATA__',
            r'<div\s+id="__next">',
            r'data-next-page=',
            r'id="__NEXT_DATA__"',
        ],
        'Nuxt.js': [
            r'_nuxt/',
            r'__NUXT__',
            r'data-nuxt-',
            r'id="__NUXT__"',
        ],
        'Gatsby': [
            r'__GATSBY',
            r'gatsby-image-wrapper',
            r'id="gatsby-focus-wrapper"',
        ],
        'SvelteKit': [
            r'__SVELTEKIT__',
            r'data-sveltekit-',
            r'svelte-',
        ],
        'Astro': [
            r'__ASTRO__',
            r'astro-[a-z]',
        ],
        'Remix': [
            r'__remixContext',
            r'data-remix-route',
            r'remix-run',
        ],
        'React': [
            r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
            r'data-reactroot',
            r'data-reactid',
            r'/static/js/main\.\w+\.js',
            r'react\.production(?:\.min)?\.js',
            r'id=["\']root["\']',
            r'__reactFiber',
            r'__NEXT_DATA__',
        ],
        'Laravel': [
            r'csrf-token',
            r'xsrf-token',
            r'__laravel',
            r'livewire',
            r'data-turbolinks-track',
        ],
        'Django': [
            r'csrftoken',
            r'__django',
            r'var\s+django\s*=',
        ],
        'Flask': [
            r'__flask',
            r'Flask',
        ],
        'ASP.NET': [
            r'__VIEWSTATE',
            r'__EVENTVALIDATION',
            r'__RequestVerificationToken',
            r'X-AspNet-Version',
        ],
        'WordPress': [
            r'/wp-content/',
            r'/wp-includes/',
            r'/wp-json/',
            r'/wp-admin/',
            r'/wp-login',
        ],
        'Shopify': [
            r'shopify\.com/',
            r'myshopify\.com/',
            r'cdn\.shopify\.com/',
            r'Shopify\.',
        ],
        'Drupal': [
            r'Drupal\.settings',
            r'drupal\.js',
            r'sites/default/',
        ],
        'Joomla': [
            r'com_content',
            r'com_user',
            r'/components/com_',
        ],
        'Wix': [
            r'Wix\.com',
            r'wixstatic\.com',
            r'wix\.js',
        ],
        'Squarespace': [
            r'squarespace\.com',
            r'static1\.squarespace',
        ],
        'Webpack': [
            r'webpackJsonp',
            r'__webpack_require__',
            r'webpack/chunk',
        ],
        'Vite': [
            r'vite@',
            r'@vitejs',
            r'__vite_',
        ],
        'Prerender': [
            r'prerender\.io',
            r'prerender_',
        ],
        'Supabase': [
            r'supabase\.co',
            r'supabase\.js',
            r'@supabase',
        ],
        'Firebase': [
            r'firebase\.io',
            r'firebaseapp\.com',
            r'firebase\.js',
            r'@firebase',
        ],
        'GraphQL': [
            r'__typename',
            r'introspectionQuery',
            r'graphql',
        ],
        'Tailwind CSS': [
            r'@tailwind\s+(?:base|components|utilities|screen)',
            r'class="[^"]*(?:sm|md|lg|xl|2xl|dark|hover|focus|active|group-hover|focus-within):\w+',
            r'class="[^"]*[mp][trblxy]?-\d+[^"]*',
            r'tailwindcss',
            r'cdn\.tailwindcss\.com',
        ],
        'Lucide': [
            r'class="[^"]*lucide-[^"]*"',
            r'lucide-react',
            r'@lucide/web',
            r'lucide\.umd',
            r'cdn\.jsdelivr\.net/npm/lucide',
        ],
    }

    def detect(self, url='', html='', headers=None, scripts=None, meta_tags=None, cookies=None):
        if headers is None:
            headers = {}
        if scripts is None:
            scripts = []
        if meta_tags is None:
            meta_tags = {}
        if cookies is None:
            cookies = {}

        detected = {}
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        html_lower = html.lower()
        url_lower = url.lower()

        for tech_name, patterns in self.technologies.items():
            confidence = 0
            matches = []

            html_pats = patterns.get('html', '')
            if html_pats and self._match_any(html_pats, html):
                confidence = max(confidence, 100)
                matches.append('html')

            text_pats = patterns.get('text', '')
            if text_pats and self._match_any(text_pats, html):
                confidence = max(confidence, 100)
                matches.append('text')

            url_pats = patterns.get('url', '')
            if url_pats and self._match_any(url_pats, url_lower):
                confidence = max(confidence, 100)
                matches.append('url')

            for header_name, header_pattern in patterns.get('headers', {}).items():
                hn = header_name.lower()
                if hn in headers_lower:
                    if isinstance(header_pattern, str):
                        header_pattern = [header_pattern]
                    for hp in header_pattern:
                        try:
                            if re.search(hp, headers_lower[hn], re.IGNORECASE):
                                confidence = max(confidence, 100)
                                matches.append(f'header:{header_name}')
                                break
                        except re.error:
                            pass

            for meta_name, meta_pattern in patterns.get('meta', {}).items():
                mn = meta_name.lower()
                if mn in meta_tags:
                    if isinstance(meta_pattern, str):
                        meta_pattern = [meta_pattern]
                    for mp in meta_pattern:
                        try:
                            if re.search(mp, meta_tags[mn], re.IGNORECASE):
                                confidence = max(confidence, 100)
                                matches.append(f'meta:{meta_name}')
                                break
                        except re.error:
                            pass

            ss_pats = patterns.get('scriptSrc', [])
            if isinstance(ss_pats, str):
                ss_pats = [ss_pats]
            for ssp in ss_pats:
                for script in scripts:
                    try:
                        if re.search(ssp, script, re.IGNORECASE):
                            confidence = max(confidence, 100)
                            matches.append('scriptSrc')
                            break
                    except re.error:
                        pass
                if matches and matches[-1] == 'scriptSrc':
                    break

            for cookie_name, cookie_pattern in patterns.get('cookies', {}).items():
                cn = cookie_name.lower()
                if cn in cookies:
                    if isinstance(cookie_pattern, str):
                        cookie_pattern = [cookie_pattern]
                    for cp in cookie_pattern:
                        try:
                            if re.search(cp, cookies[cn], re.IGNORECASE):
                                confidence = max(confidence, 100)
                                matches.append(f'cookie:{cookie_name}')
                                break
                        except re.error:
                            pass

            if matches:
                result = {
                    'name': tech_name,
                    'confidence': confidence,
                    'matches': matches,
                    'categories': patterns.get('cats', []),
                }
                if 'version' in patterns:
                    result['version'] = patterns['version']
                if 'implies' in patterns:
                    result['implies'] = patterns['implies']
                detected[tech_name] = result

        is_block_page = self._is_security_block(html)

        if not is_block_page:
            for tech_name, fallback_patterns in self.HTML_FALLBACKS.items():
                if tech_name not in detected:
                    for fp in fallback_patterns:
                        try:
                            if re.search(fp, html, re.IGNORECASE):
                                cat_ids = self.technologies.get(tech_name, {}).get('cats', []) or self.FALLBACK_CATEGORIES.get(tech_name, [])
                                detected[tech_name] = {
                                    'name': tech_name,
                                    'confidence': 80,
                                    'matches': [f'html_fallback:{fp}'],
                                    'categories': cat_ids,
                                    'implies': self.technologies.get(tech_name, {}).get('implies', []),
                                }
                                break
                        except re.error:
                            pass

        HEADER_FALLBACKS = {
            'Vercel': [('server', 'vercel'), ('x-vercel', '.*')],
            'Next.js': [('x-nextjs-prerender', '.*'), ('x-nextjs-stale-time', '.*'), ('x-matched-path', '.*')],
            'Netlify': [('server', 'netlify'), ('x-nf-request-id', '.*')],
            'Cloudflare': [('server', 'cloudflare'), ('cf-ray', '.*')],
            'CloudFront': [('server', 'cloudfront'), ('x-amz-cf-id', '.*'), ('x-cache', '.*')],
            'Node.js': [('x-powered-by', 'express|node'), ('server', 'node')],
            'Python': [('x-powered-by', 'python|django|flask|wsgi'), ('server', 'python|gunicorn|uwsgi')],
            'Ruby': [('x-powered-by', 'ruby|rails|passenger|rack'), ('server', 'passenger|unicorn')],
            'PHP': [('x-powered-by', 'php'), ('server', 'php|apache')],
            'ASP.NET': [('x-powered-by', 'asp\\.net'), ('x-aspnet-version', '.*'), ('server', 'iis|microsoft-iis')],
            'Nginx': [('server', 'nginx')],
            'Apache': [('server', 'apache')],
            'GitHub Pages': [('server', 'github\\.com')],
            'Heroku': [('via', 'heroku'), ('connect-via', 'heroku')],
            'Supabase': [('content-security-policy', r'supabase\.co')],
            'Google Analytics': [('content-security-policy', r'google-analytics\.com')],
        }

        for tech_name, checks in HEADER_FALLBACKS.items():
            if tech_name not in detected:
                for hname, hpattern in checks:
                    hn = hname.lower()
                    if hn in headers_lower:
                        try:
                            if re.search(hpattern, headers_lower[hn], re.IGNORECASE):
                                cat_ids = self.technologies.get(tech_name, {}).get('cats', []) or self.FALLBACK_CATEGORIES.get(tech_name, [])
                                detected[tech_name] = {
                                    'name': tech_name,
                                    'confidence': 90,
                                    'matches': [f'header_fallback:{hname}'],
                                    'categories': cat_ids,
                                    'implies': self.technologies.get(tech_name, {}).get('implies', []),
                                }
                                break
                        except re.error:
                            pass

        for tech_name, info in list(detected.items()):
            for implied in info.get('implies', []):
                if isinstance(implied, str):
                    imp_name = implied.split('\\;')[0]
                    if imp_name not in detected and imp_name in self.technologies:
                        detected[imp_name] = {
                            'name': imp_name,
                            'confidence': info['confidence'],
                            'matches': [f'implied by {tech_name}'],
                            'categories': self.technologies[imp_name].get('cats', []),
                            'implied': True,
                        }

        return detected

    def get_category_name(self, cat_id):
        if isinstance(self.categories, dict) and str(cat_id) in self.categories:
            return self.categories[str(cat_id)].get('name', f'Category {cat_id}')
        return f'Category {cat_id}'
