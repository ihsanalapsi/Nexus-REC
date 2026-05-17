import requests
import re
import json
import tempfile
import os
import zipfile
import io


class APKRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def find_apk_references(self):
        apks = []
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text

            apk_links = re.findall(
                r'(https?://[^"\'\s<>]+\.(?:apk|aab))(?:\?[^"\'\s<>]*)?',
                html, re.IGNORECASE
            )
            for link in set(apk_links):
                apks.append({
                    'url': link,
                    'source': 'html_link',
                    'method': 'direct_download',
                })

            apk_patterns = re.findall(
                r'["\']([^"\']*\.(?:apk|aab))["\']',
                html, re.IGNORECASE
            )
            for rel_path in set(apk_patterns):
                full_url = rel_path if rel_path.startswith('http') else \
                    self.target_url.rstrip('/') + '/' + rel_path.lstrip('/')
                if full_url not in [a['url'] for a in apks]:
                    apks.append({
                        'url': full_url,
                        'source': 'relative_path',
                        'method': 'direct_download',
                    })

            app_links = re.findall(
                r'https?://play\.google\.com/store/apps/details\?id=([a-zA-Z0-9._-]+)',
                html
            )
            for app_id in set(app_links):
                apks.append({
                    'url': f'https://play.google.com/store/apps/details?id={app_id}',
                    'source': 'google_play',
                    'package': app_id,
                    'method': 'play_store',
                })

            app_links_direct = re.findall(
                r'https?://play\.google\.com/store/apps/details\?id=([a-zA-Z0-9._-]+)',
                html
            )
            for app_id in set(app_links_direct):
                if not any(a.get('package') == app_id for a in apks):
                    apks.append({
                        'url': f'https://play.google.com/store/apps/details?id={app_id}',
                        'source': 'google_play',
                        'package': app_id,
                        'method': 'play_store',
                    })

            ios_links = re.findall(
                r'https?://apps\.apple\.com/[a-z]{2}/app/[^/]+/id(\d+)',
                html
            )
            for app_id in set(ios_links):
                apks.append({
                    'url': f'https://apps.apple.com/app/id{app_id}',
                    'source': 'app_store',
                    'bundle_id': app_id,
                    'method': 'app_store',
                    'platform': 'ios',
                })

        except:
            pass

        self.results['apk_references'] = apks
        return apks

    def extract_from_apk_url(self, apk_url):
        findings = {
            'url': apk_url,
            'status': 'failed',
            'extracted_endpoints': [],
            'extracted_keys': [],
            'extracted_urls': [],
            'packages': [],
            'permissions': [],
        }

        try:
            r = requests.get(apk_url, timeout=30, stream=True,
                headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code != 200:
                findings['error'] = f'HTTP {r.status_code}'
                return findings

            content_type = r.headers.get('Content-Type', '')
            if 'html' in content_type:
                findings['error'] = 'Redirected to HTML page, not an APK'
                return findings

            content = r.content
            if len(content) < 1000:
                findings['error'] = 'File too small to be APK'
                return findings

            findings['size'] = len(content)
            findings['status'] = 'downloaded'

            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    for name in zf.namelist():
                        if name.endswith('.dex'):
                            try:
                                dex_data = zf.read(name)
                                text = self._extract_strings(dex_data)
                                apis = self._find_api_endpoints(text)
                                keys = self._find_secret_keys(text)
                                urls = self._find_urls(text)

                                findings['extracted_endpoints'].extend(apis)
                                findings['extracted_keys'].extend(keys)
                                findings['extracted_urls'].extend(urls)
                            except:
                                pass

                        if 'AndroidManifest.xml' in name:
                            findings['manifest_extracted'] = True

                        if name.endswith('.xml'):
                            try:
                                xml_data = zf.read(name)
                                text = self._extract_strings(xml_data)
                                urls = self._find_urls(text)
                                findings['extracted_urls'].extend(urls)
                            except:
                                pass

                        if name.startswith('res/') or name.startswith('assets/'):
                            try:
                                file_data = zf.read(name)
                                text = self._extract_strings(file_data)
                                apis = self._find_api_endpoints(text)
                                keys = self._find_secret_keys(text)
                                urls = self._find_urls(text)
                                findings['extracted_endpoints'].extend(apis)
                                findings['extracted_keys'].extend(keys)
                                findings['extracted_urls'].extend(urls)
                            except:
                                pass

                if 'assets/index.android.bundle' in zf.namelist():
                    try:
                        bundle_data = zf.read('assets/index.android.bundle')
                        bundle_text = self._extract_strings(bundle_data)
                        apis = self._find_api_endpoints(bundle_text)
                        keys = self._find_secret_keys(bundle_text)
                        urls = self._find_urls(bundle_text)
                        findings['extracted_endpoints'].extend(apis)
                        findings['extracted_keys'].extend(keys)
                        findings['extracted_urls'].extend(urls)
                        findings['react_native_bundle'] = True
                    except:
                        pass

            except zipfile.BadZipFile:
                findings['error'] = 'Not a valid ZIP/APK file'

        except:
            pass

        findings['extracted_endpoints'] = list(set(findings['extracted_endpoints']))
        findings['extracted_keys'] = list(set(findings['extracted_keys']))
        findings['extracted_urls'] = list(set(findings['extracted_urls']))

        return findings

    def _extract_strings(self, data):
        try:
            return data.decode('utf-8', errors='ignore')
        except:
            try:
                return data.decode('latin-1', errors='ignore')
            except:
                return ''

    def _find_api_endpoints(self, text):
        endpoints = []
        patterns = [
            r'https?://[a-zA-Z0-9.-]+/api/[a-zA-Z0-9/_-]+',
            r'https?://[a-zA-Z0-9.-]+/v[0-9]/[a-zA-Z0-9/_-]+',
            r'https?://[a-zA-Z0-9.-]+/graphql',
            r'https?://[a-zA-Z0-9.-]+/rest/v[0-9]/',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text)
            endpoints.extend(matches)
        return endpoints

    def _find_secret_keys(self, text):
        keys = []
        patterns = [
            (r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'supabase_jwt'),
            (r'sk_live_[a-zA-Z0-9]+', 'stripe_live'),
            (r'sk_test_[a-zA-Z0-9]+', 'stripe_test'),
            (r'pk_live_[a-zA-Z0-9]+', 'stripe_pk_live'),
            (r'pk_test_[a-zA-Z0-9]+', 'stripe_pk_test'),
            (r'AIza[0-9A-Za-z_-]{35}', 'google_api'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'SECRET[_ ]KEY["\']?\s*[:=]\s*["\'][^"\']+', 'generic_secret'),
            (r'API[_ ]KEY["\']?\s*[:=]\s*["\'][^"\']+', 'generic_api_key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'github_token'),
            (r'gho_[a-zA-Z0-9]{36}', 'github_oauth'),
            (r'xox[bpras]-[0-9a-zA-Z-]+', 'slack_token'),
        ]
        for pattern, key_type in patterns:
            matches = re.findall(pattern, text)
            for m in matches[:5]:
                keys.append({'type': key_type, 'value': m[:40] + '...' if len(m) > 40 else m})
        return keys

    def _find_urls(self, text):
        urls = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9/._-]*)?', text)
        filtered = []
        for url in urls:
            if self.domain not in url:
                filtered.append(url)
        return filtered[:50]

    def run_all(self):
        self.find_apk_references()
        apks = self.results.get('apk_references', [])
        direct_apks = [a for a in apks if a.get('method') == 'direct_download']

        extracted_data = []
        for apk in direct_apks[:3]:
            result = self.extract_from_apk_url(apk['url'])
            if result.get('extracted_endpoints') or result.get('extracted_keys'):
                extracted_data.append(result)

        self.results['apk_extracted'] = extracted_data

        all_endpoints = []
        all_keys = []
        for ed in extracted_data:
            all_endpoints.extend(ed.get('extracted_endpoints', []))
            all_keys.extend(ed.get('extracted_keys', []))

        if all_endpoints:
            self.results['apk_api_endpoints'] = list(set(all_endpoints))
        if all_keys:
            self.results['apk_secrets'] = all_keys

        return self.results
