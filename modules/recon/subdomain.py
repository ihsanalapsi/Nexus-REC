import requests
import socket
import re
import concurrent.futures
from urllib.parse import urlparse


class SubdomainRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def enumerate_subdomains(self, wordlist=None):
        if wordlist is None:
            wordlist = [
                'www', 'api', 'admin', 'dev', 'staging', 'test', 'qa', 'uat',
                'app', 'web', 'portal', 'dashboard', 'cdn', 'static', 'assets',
                'img', 'images', 'media', 'files', 'upload', 'download',
                'mail', 'email', 'smtp', 'pop3', 'imap', 'webmail',
                'vpn', 'remote', 'ssh', 'secure', 'login', 'auth',
                'pay', 'payment', 'billing', 'checkout', 'cart',
                'shop', 'store', 'product', 'service', 'support',
                'help', 'docs', 'documentation', 'wiki', 'blog',
                'news', 'forum', 'community', 'status', 'health',
                'monitor', 'metrics', 'analytics', 'tracking', 'logs',
                'search', 'suggest', 'autocomplete', 'feed', 'rss',
                'graphql', 'api-gateway', 'gateway', 'proxy',
                'internal', 'corp', 'corporate', 'partner', 'partners',
                'vendor', 'vendors', 'supplier', 'erp', 'crm',
                'hr', 'payroll', 'intranet', 'extranet',
                'beta', 'alpha', 'demo', 'sandbox', 'playground',
                'stage', 'preprod', 'pre-prod', 'production', 'prod',
                'us', 'eu', 'asia', 'uk', 'de', 'fr', 'jp', 'cn',
                'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2',
                'mobile', 'm', 'wap', 'touch', 'amp',
                'cdn', 'static', 'img', 'css', 'js', 'font',
                'assets', 'media', 'upload', 'download', 'video',
                'api-v1', 'api-v2', 'api-v3', 'v1', 'v2', 'v3',
                'ws', 'wss', 'socket', 'websocket', 'stream',
                'notify', 'notification', 'push', 'sms',
                'auth', 'oauth', 'saml', 'sso', 'openid',
                'adminer', 'phpmyadmin', 'phpadmin', 'pma',
                'redis', 'redis-admin', 'rabbitmq', 'kibana',
                'elastic', 'elasticsearch', 'grafana', 'prometheus',
                'jenkins', 'gitlab', 'bitbucket', 'jira', 'confluence',
                'swagger', 'swagger-ui', 'api-docs', 'docs-api',
                'download', 'uploads', 'files', 'old', 'legacy',
                'archive', 'backup', 'monitor', 'firebase',
                'auth2', 'sso', 'oauth', 'track', 'tracking',
                'analytics', 'metrics', 'player', 'console',
                'mobile', 'm', 'app',
            ]
        found = []
        not_done = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {}
            for sub in wordlist:
                fqdn = f"{sub}.{self.domain}"
                futures[executor.submit(self._check_subdomain, fqdn)] = fqdn
            done, not_done = concurrent.futures.wait(futures, timeout=20)
            for future in done:
                result = future.result()
                if result:
                    found.append(result)
            for f in not_done:
                f.cancel()
        if not_done:
            self.results['dns_timeout_cancelled'] = len(not_done)
        found.sort(key=lambda x: x.get('subdomain', ''))
        self.results['subdomains'] = found
        self.results['total_found'] = len(found)
        return found

    def _resolve_dns(self, fqdn, timeout=5):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                f = ex.submit(socket.gethostbyname, fqdn)
                return f.result(timeout=timeout)
        except (concurrent.futures.TimeoutError, socket.gaierror, OSError):
            return None

    def _check_subdomain(self, fqdn):
        result = {'subdomain': fqdn}
        ip = self._resolve_dns(fqdn)
        if ip is None:
            return None
        result['ip'] = ip
        result['resolves'] = True
        try:
            url = f"https://{fqdn}"
            r = requests.get(url, timeout=5, allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0'})
            result['http_status'] = r.status_code
            result['server'] = r.headers.get('Server', '')
            result['content_length'] = len(r.content)
            result['accessible'] = r.status_code in [200, 301, 302, 403, 401]
        except requests.RequestException:
            try:
                url = f"http://{fqdn}"
                r = requests.get(url, timeout=5, allow_redirects=False)
                result['http_status'] = r.status_code
                result['accessible'] = True
            except:
                result['http_status'] = None
                result['accessible'] = False
        return result

    def check_certificate_transparency(self):
        crt_sh_url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        subdomains = set()
        try:
            r = requests.get(crt_sh_url, timeout=15,
                headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                try:
                    data = r.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip()
                            if sub.endswith(self.domain) and '*' not in sub:
                                subdomains.add(sub)
                except (json.JSONDecodeError, ValueError):
                    # Fallback: regex parse when JSON fails
                    import re as regex
                    raw = r.text
                    name_values = regex.findall(r'"name_value"\s*:\s*"([^"]+)"', raw)
                    for nv in name_values:
                        for sub in nv.split('\\n'):
                            sub = sub.strip()
                            if sub.endswith(self.domain) and '*' not in sub:
                                subdomains.add(sub)
        except:
            pass
        self.results['crt_sh_subdomains'] = sorted(subdomains)
        self.results['crt_sh_total'] = len(subdomains)
        return self.results

    def extract_from_js_apis(self, js_api_urls=None):
        found = set()
        if js_api_urls:
            for api_url in js_api_urls:
                parsed = urlparse(api_url)
                hostname = parsed.hostname
                if hostname and hostname != self.domain and hostname.endswith('.' + self.domain):
                    found.add(hostname)
        self.results['js_discovered_subdomains'] = sorted(found) if found else []
        return self.results

    def discover_related_domains(self, js_api_urls=None):
        related = set()
        if js_api_urls:
            platform_domains = [
                '.railway.app', '.herokuapp.com', '.fly.dev', '.onrender.com',
                '.vercel.app', '.netlify.app', '.supabase.co', '.supabase.in',
                '.firebaseio.com', '.firestore.googleapis.com',
                '.cloudfunctions.net', '.lambda-url.', '.execute-api.',
            ]
            for api_url in js_api_urls:
                parsed = urlparse(api_url)
                hostname = parsed.hostname
                if not hostname:
                    continue
                if hostname == self.domain or hostname.endswith('.' + self.domain):
                    continue
                if self._is_noise_domain(hostname):
                    continue
                host_lower = hostname.lower()
                if any(pd in host_lower for pd in platform_domains):
                    continue
                related.add(hostname)
        self.results['related_domains'] = {
            'discovered': sorted(related),
            'total': len(related),
        } if related else {}
        return self.results

    def _is_noise_domain(self, hostname):
        noise_domains = [
            'react.dev', 'github.com', 'facebook.com', 'instagram.com',
            'linkedin.com', 'twitter.com', 'x.com', 'youtube.com',
            'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com',
            'google-analytics.com', 'cloudflare.com', 'cloudflareinsights.com',
            'w3.org', 'apple.com', 'mozilla.org', 'githubusercontent.com',
            'fonts.googleapis.com', 'fonts.gstatic.com', 'jsdelivr.net',
            'unpkg.com', 'cdnjs.cloudflare.com', 'npmjs.com',
            'medium.com', 'stackoverflow.com', 'stackexchange.com',
            'getbootstrap.com', 'tailwindcss.com', 'vitejs.dev',
            'nextjs.org', 'vercel.com', 'netlify.com',
        ]
        host_lower = hostname.lower()
        for nd in noise_domains:
            if host_lower == nd or host_lower.endswith('.' + nd):
                return True
        return False

    def _is_backend_candidate(self, hostname):
        if hostname.endswith('.' + self.domain):
            return not self._is_noise_domain(hostname)
        if self._is_noise_domain(hostname):
            return False
        backend_keywords = ['api', 'backend', 'server', 'gateway', 'service',
                           'engine', 'worker', 'compute', 'function', 'lambda',
                           'database', 'db', 'storage', 'bucket', 'graphql',
                           'webhook', 'socket', 'stream', 'realtime', 'proxy']
        host_lower = hostname.lower()
        for kw in backend_keywords:
            if kw in host_lower:
                return True
        platform_domains = [
            '.railway.app', '.herokuapp.com', '.fly.dev', '.onrender.com',
            '.vercel.app', '.netlify.app', '.supabase.co', '.supabase.in',
            '.firebaseio.com', '.firestore.googleapis.com',
            '.cloudfunctions.net', '.lambda-url.', '.execute-api.',
        ]
        for pd in platform_domains:
            if pd in host_lower:
                return True
        return False

    def discover_backends_from_js(self, js_api_urls=None):
        backends = []
        if js_api_urls:
            seen = set()
            for api_url in js_api_urls:
                parsed = urlparse(api_url)
                hostname = parsed.hostname
                if not hostname or hostname in seen:
                    continue
                seen.add(hostname)
                if not self._is_backend_candidate(hostname):
                    continue
                bip = self._resolve_dns(hostname)
                if bip:
                    backends.append({
                        'url': f"{parsed.scheme}://{parsed.netloc}",
                        'hostname': hostname,
                        'ip': bip,
                        'source': 'js_analysis',
                    })
                else:
                    backends.append({
                        'url': f"{parsed.scheme}://{parsed.netloc}",
                        'hostname': hostname,
                        'ip': 'unresolved',
                        'source': 'js_analysis',
                    })
        self.results['backend_discovered'] = backends
        return self.results

    def run_all(self, js_api_urls=None):
        self.enumerate_subdomains()
        self.check_certificate_transparency()
        return self.results
