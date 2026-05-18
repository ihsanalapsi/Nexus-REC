import requests
import socket
import re
import concurrent.futures
from urllib.parse import urljoin


class AdminScanRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False
        self.max_workers = 20

    def find_admin_subdomains(self):
        admin_prefixes = [
            'admin', 'adminer', 'admin-console', 'admin-console-1',
            'admin-panel', 'admin-portal', 'admin-ui', 'admin-web',
            'admin1', 'admin2', 'admin3', 'admin-old', 'admin-backup',
            'administrator', 'admins',
            'backend', 'backoffice', 'back-office',
            'cms', 'cms-admin', 'control', 'controlpanel',
            'cp', 'cpanel', 'cpanel2',
            'dash', 'dashboard', 'dashboard2', 'dashboard-admin',
            'dbadmin', 'directadmin',
            'enterprise', 'erp',
            'internal', 'internal-api', 'intranet',
            'manage', 'management', 'manager',
            'master', 'master-admin',
            'monitor', 'monitoring',
            'operator', 'operators',
            'panel', 'panel-admin', 'panel2',
            'phpadmin', 'phpmyadmin', 'pma',
            'portal', 'portal-admin', 'portal-1',
            'private', 'protected', 'proxy-admin',
            'root', 'root-admin',
            'sso', 'sso-admin', 'sso-dashboard', 'sso-portal',
            'staff', 'staff-portal', 'staff-area',
            'super', 'superadmin', 'super-user',
            'support-admin',
            'sysadmin', 'system',
            'ubiquiti', 'unifi',
            'webadmin', 'webmin', 'whm',
            'vpn-admin',
        ]

        findings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, 20)) as executor:
            futures = {}
            for prefix in admin_prefixes:
                fqdn = f'{prefix}.{self.domain}'
                futures[executor.submit(self._check_subdomain, fqdn)] = fqdn

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        self.results['admin_subdomains'] = findings
        return findings

    def _check_subdomain(self, fqdn):
        result = None
        try:
            ip = socket.gethostbyname(fqdn)
            result = {
                'subdomain': fqdn,
                'ip': ip,
            }

            for proto in ['https', 'http']:
                try:
                    url = f'{proto}://{fqdn}'
                    r = requests.get(url, timeout=8, allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'})
                    result['http_status'] = r.status_code
                    result['url'] = url
                    result['server'] = r.headers.get('Server', '')
                    result['content_type'] = r.headers.get('Content-Type', '')
                    result['content_length'] = len(r.content)
                    result['title'] = self._extract_title(r.text)
                    result['redirect_url'] = r.url if r.url != url else None

                    if 'admin' in r.text.lower()[:2000] or 'login' in r.text.lower()[:2000]:
                        result['has_login'] = True
                    if r.status_code in [401, 403]:
                        result['authentication_required'] = True

                    if r.status_code == 200 and len(r.content) > 1000:
                        result['accessible'] = True
                        if 'login' in r.text.lower()[:3000]:
                            result['page_type'] = 'login_page'
                        elif 'dashboard' in r.text.lower()[:3000]:
                            result['page_type'] = 'dashboard'
                        elif 'admin' in r.text.lower()[:3000]:
                            result['page_type'] = 'admin_panel'
                        else:
                            result['page_type'] = 'unknown'

                    break
                except:
                    continue
        except:
            pass

        return result

    def _extract_title(self, html):
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ''

    def scan_admin_paths(self):
        admin_paths = [
            '/admin', '/admin/', '/admin.php', '/admin.cgi',
            '/admin/login', '/admin/login.php',
            '/admin/dashboard', '/admin/dashboard.php',
            '/admin/panel', '/admin/panel.php',
            '/admin/index.php', '/admin/index.html',
            '/admin/home', '/admin/home.php',
            '/administration', '/administrator',
            '/backend', '/backoffice',
            '/cms', '/cms/admin',
            '/control', '/controlpanel', '/cp',
            '/dash', '/dashboard', '/dashboard.php',
            '/dbadmin', '/db-manager',
            '/login', '/login.php', '/login.aspx',
            '/adminer.php', '/adminer',
            '/manage', '/management',
            '/panel', '/panel.php',
            '/phpmyadmin', '/pma', '/phpMyAdmin',
            '/private', '/protected',
            '/secret', '/secrets',
            '/staff', '/staff-portal',
            '/superadmin', '/super-user',
            '/sysadmin', '/system',
            '/user/login', '/user/admin',
            '/webadmin', '/webmin',
            '/wp-admin', '/wp-login.php',
            '/console', '/console/',
            '/api/admin', '/api/v1/admin',
            '/.env', '/.git/config',
        ]

        findings = []
        for path in admin_paths:
            try:
                url = urljoin(self.target_url, path)
                r = requests.get(url, timeout=8, allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code in [200, 301, 302, 401, 403]:
                    ct = r.headers.get('Content-Type', '')
                    findings.append({
                        'path': path,
                        'url': url,
                        'status': r.status_code,
                        'size': len(r.content),
                        'content_type': ct,
                        'redirect_to': r.headers.get('Location', '') if r.status_code in [301, 302] else None,
                    })
            except:
                pass

        self.results['admin_paths'] = findings
        return findings

    def probe_admin_technologies(self, admin_url):
        tech = {}
        try:
            r = requests.get(admin_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            text = r.text
            headers = r.headers

            if 'wp-admin' in text or 'wp-login' in text or 'wordpress' in text.lower():
                tech['cms'] = 'WordPress'
            elif 'administrator' in text[:500] and 'joomla' in text.lower():
                tech['cms'] = 'Joomla'
            elif 'drupal' in text.lower():
                tech['cms'] = 'Drupal'
            elif 'Shopify' in text or 'shopify' in text.lower():
                tech['cms'] = 'Shopify'

            if 'laravel' in text.lower():
                tech['framework'] = 'Laravel'
            elif 'csrf-token' in headers.get('X-CSRF-TOKEN', ''):
                tech['framework'] = 'Laravel'
            elif '__next' in text.lower() or 'next.js' in text.lower():
                tech['framework'] = 'Next.js'

            if 'ASP.NET' in text or '__VIEWSTATE' in text:
                tech['framework'] = 'ASP.NET'

            if 'X-Powered-By' in headers:
                tech['powered_by'] = headers['X-Powered-By']
            if 'Server' in headers:
                tech['server'] = headers['Server']

        except:
            pass

        return tech

    def run_all(self):
        self.find_admin_subdomains()
        self.scan_admin_paths()

        admin_subs = self.results.get('admin_subdomains', [])
        accessible = [a for a in admin_subs if a.get('accessible')]
        if accessible:
            for a in accessible[:5]:
                tech = self.probe_admin_technologies(a.get('url', f'https://{a["subdomain"]}'))
                if tech:
                    a['technologies'] = tech

            self.results['accessible_admin'] = accessible

        open_paths = [p for p in self.results.get('admin_paths', []) if p['status'] == 200]
        if open_paths:
            self.results['open_admin_paths'] = open_paths

        return self.results
