import requests
import json
import re
import hashlib
from urllib.parse import urljoin

class SecretsRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self._homepage_html = None
        self._homepage_hash = None
        self._homepage_length = None

    def _fetch_homepage(self):
        if self._homepage_html is not None:
            return
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            self._homepage_html = r.text
            self._homepage_length = len(r.content)
            self._homepage_hash = hashlib.md5(r.content).hexdigest()
        except:
            pass

    def _is_spa_catchall(self, r):
        if self._homepage_length is None:
            return False
        if len(r.content) == self._homepage_length:
            if r.text == self._homepage_html:
                return True
        return False

    def find_exposed_files(self):
        self._fetch_homepage()
        sensitive_files = [
            '/.env', '/.env.example', '/.env.production', '/.env.local',
            '/.git/config', '/.git/HEAD', '/.gitignore',
            '/.aws/credentials', '/.aws/config',
            '/config.json', '/config.js', '/config.php',
            '/configuration.json', '/settings.json',
            '/database.json', '/database.yml', '/database.config',
            '/db.json', '/db.config',
            '/robots.txt', '/security.txt', '/sitemap.xml',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/package.json', '/package-lock.json', '/yarn.lock',
            '/composer.json', '/composer.lock',
            '/requirements.txt', '/Gemfile', '/Gemfile.lock',
            '/Dockerfile', '/docker-compose.yml',
            '/nginx.conf', '/web.config', '/.htaccess',
            '/swagger.json', '/swagger.yaml', '/api-docs',
            '/admin', '/administrator', '/backup',
            '/dump.sql', '/backup.sql', '/db.sql',
            '/phpinfo.php', '/info.php', '/test.php',
            '/wp-config.php', '/wp-config.bak',
            '/api/', '/api/v1/', '/api/v2/',
            '/graphql', '/playground', '/graphiql',
        ]
        found = []
        blocked = []
        for path in sensitive_files:
            try:
                url = urljoin(self.target_url, path)
                r = requests.get(url, timeout=8, allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code in [200, 301, 302]:
                    if self._is_spa_catchall(r):
                        continue
                    ct = r.headers.get('Content-Type', '')
                    size = len(r.content)
                    content_preview = r.text[:300] if size < 50000 else 'TOO_LARGE'
                    found.append({
                        'path': path, 'status': r.status_code,
                        'size': size, 'content_type': ct,
                        'preview': content_preview,
                    })
                elif r.status_code == 403:
                    blocked.append({
                        'path': path, 'status': 403,
                        'size': len(r.content), 'note': 'Blocked by edge/WAF',
                    })
            except:
                pass
        self.results['exposed_files'] = found
        self.results['blocked_paths'] = blocked
        return found

    def check_firebase(self):
        firebase_pattern = re.compile(r'(https?://[a-zA-Z0-9_-]+\.firebaseio\.com)')
        findings = []
        try:
            r = requests.get(self.target_url, timeout=10)
            matches = firebase_pattern.findall(r.text)
            for fb_url in set(matches):
                test_url = f"{fb_url}/.json?shallow=true"
                try:
                    r2 = requests.get(test_url, timeout=10)
                    if r2.status_code == 200 and r2.text not in ['null', '{}']:
                        findings.append({
                            'firebase_url': fb_url,
                            'open': True,
                            'data_preview': r2.text[:300],
                        })
                    else:
                        findings.append({
                            'firebase_url': fb_url,
                            'open': False,
                        })
                except:
                    pass
        except:
            pass
        self.results['firebase'] = findings
        return findings

    def validate_google_api_keys(self):
        api_key_pattern = re.compile(r'AIza[0-9A-Za-z_-]{35}')
        findings = []
        try:
            r = requests.get(self.target_url, timeout=10)
            matches = api_key_pattern.findall(r.text)
            for key in set(matches):
                test_url = f'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}'
                try:
                    r2 = requests.get(test_url, timeout=10)
                    data = r2.json()
                    status = data.get('status', '')
                    if status == 'OK':
                        findings.append({
                            'key': key[:20] + '...',
                            'valid': True,
                            'restricted': False,
                            'note': 'KEY FULLY ACCESSIBLE - Can be abused'
                        })
                    elif status == 'REQUEST_DENIED':
                        findings.append({
                            'key': key[:20] + '...',
                            'valid': True,
                            'restricted': True,
                            'note': 'Key exists but restricted'
                        })
                except:
                    pass
        except:
            pass
        self.results['google_api_keys'] = findings
        return findings

    def detect_tracking_ids(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text
            html_lower = html.lower()

            ga = re.search(r'G-[A-Z0-9]{7,15}', html)
            if ga:
                findings['google_analytics_id'] = ga.group(0)

            gtm = re.search(r'GTM-[A-Z0-9]{5,10}', html)
            if gtm:
                findings['google_tag_manager'] = gtm.group(0)

            fb_app = re.search(r'fb:app_id["\'].*?content=["\'](\d+)["\']', html, re.IGNORECASE)
            if not fb_app:
                fb_app = re.search(r'facebook.*?app.*?(\d{10,20})', html_lower)
            if fb_app:
                findings['facebook_app_id'] = fb_app.group(1)

            fb_page = re.search(r'facebook\.com/(?:profile\.php\?id=|pages/|pg/)(\d+)', html_lower)
            if fb_page:
                findings['facebook_page_id'] = fb_page.group(1)

            site_ver = re.search(r'google-site-verification["\'].*?content=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if site_ver:
                findings['google_site_verification'] = site_ver.group(1)

            fb_pixel = re.search(r'fbq\(["\']init["\']\s*,\s*["\'](\d+)["\']', html)
            if fb_pixel:
                findings['facebook_pixel_id'] = fb_pixel.group(1)

        except:
            pass
        self.results['tracking_ids'] = findings
        return findings

    def extract_schema_org(self):
        findings = []
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            schemas = re.findall(
                r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                r.text, re.DOTALL | re.IGNORECASE
            )
            for s in schemas:
                try:
                    data = json.loads(s)
                    findings.append({
                        'type': data.get('@type', 'Unknown'),
                        'name': data.get('name', ''),
                        'rating': data.get('aggregateRating', {}),
                        'data': str(data)[:500],
                    })
                except:
                    pass
        except:
            pass
        self.results['schema_org'] = findings
        return findings

    def decode_cfemail(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            cf_email = re.search(r'data-cfemail=["\']([a-f0-9]+)["\']', r.text)
            if cf_email:
                encoded = cf_email.group(1)
                key = int(encoded[:2], 16)
                decoded = ''.join(chr(int(encoded[i:i+2], 16) ^ key) for i in range(2, len(encoded), 2))
                findings['encoded'] = encoded
                findings['decoded'] = decoded
        except:
            pass
        self.results['cfemail'] = findings
        return findings

    def extract_infra_attrs(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text
            machines = re.findall(r'data-machine=["\']([^"\']+)["\']', html)
            if machines:
                findings['internal_machine_names'] = list(set(machines))
            data_attrs = re.findall(r'(data-(?:server|host|node|env|app|role))=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if data_attrs:
                findings['infra_data_attrs'] = list(set(data_attrs))
        except:
            pass
        self.results['infra_attrs'] = findings
        return findings

    def extract_search_schema(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            schemas = re.findall(
                r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                r.text, re.DOTALL | re.IGNORECASE
            )
            for s in schemas:
                try:
                    data = json.loads(s)
                    if data.get('@type') == 'WebSite':
                        sa = data.get('potentialAction', {})
                        if sa.get('@type') == 'SearchAction':
                            findings['search_action'] = {
                                'target': sa.get('target', ''),
                                'query_input': sa.get('query-input', ''),
                            }
                except:
                    pass
        except:
            pass
        self.results['search_schema'] = findings
        return findings

    def run_all(self):
        self.find_exposed_files()
        self.check_firebase()
        self.validate_google_api_keys()
        self.detect_tracking_ids()
        self.extract_schema_org()
        self.decode_cfemail()
        self.extract_infra_attrs()
        self.extract_search_schema()
        return self.results
