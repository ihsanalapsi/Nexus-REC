import requests
import socket
import re
import concurrent.futures


class DNSDetritusRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.stealth = False
        self.max_workers = 5

    def check_cloudflare_legacy(self):
        cf_octets = {
            '188.114', '173.245', '103.21', '103.22', '103.31',
            '141.101', '108.162', '190.93', '197.234', '198.41',
            '162.158', '104.16', '104.24', '172.64', '131.0',
        }

        legacy_prefixes = [
            'cdn', 'cdn2', 'cdn3', 'static', 'static2', 'static3',
            'download', 'downloads', 'dl', 'files', 'file',
            'media', 'media2', 'img', 'img2', 'images',
            'assets', 'assets2', 'css', 'js', 'font',
            'upload', 'uploads', 'backup', 'backups',
            'old', 'old-site', 'old-site-1', 'legacy',
            'archive', 'archives', 'beta-old', 'dev-old',
            'staging-old', 'test-old', 'demo-old',
            'mail.old', 'mail2', 'mail3',
            'support', 'help', 'helpdesk',
            'forum', 'forums', 'community',
            'wiki', 'docs-old', 'docs-legacy',
            'shop', 'store', 'cart',
            'm', 'mobile', 'wap',
            'ns1', 'ns2', 'ns3', 'ns4',
            'pop3', 'smtp', 'imap',
            'vpn', 'remote', 'remote2',
            'webmail', 'webmail2', 'roundcube',
            'admin-old', 'dashboard-old',
            'analytics', 'stats', 'log',
            'monitor', 'monitoring', 'status',
            'jenkins', 'gitlab-old', 'jira-old',
            'redirect', 'redirects', 'track', 'tracking',
        ]

        findings = []
        for prefix in legacy_prefixes:
            fqdn = f'{prefix}.{self.domain}'
            try:
                ips = socket.gethostbyname_ex(fqdn)[2]
                for ip in ips:
                    ip_start = '.'.join(ip.split('.')[:2])
                    service = 'Cloudflare' if ip_start in cf_octets else 'Unknown'
                    findings.append({
                        'subdomain': fqdn,
                        'ip': ip,
                        'service': service,
                        'type': 'possible_detritus',
                        'confidence': 'medium' if service == 'Cloudflare' else 'low',
                        'note': f'Legacy subdomain still resolving ({service})',
                    })
                    break
            except:
                pass

        self.results['cloudflare_detritus'] = findings
        return findings

    def check_non_cloudflare_legacy(self):
        findings = []
        legacy_dns_types = [
            'download.symarket.app', 'cdn.symarket.app',
        ]

        for ld in legacy_dns_types:
            parts = ld.split('.')
            if len(parts) >= 2:
                prefix = parts[0]
                fqdn = f'{prefix}.{self.domain}'
                try:
                    ip = socket.gethostbyname(fqdn)
                    try:
                        r = requests.get(f'https://{fqdn}', timeout=8, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'})
                        status = r.status_code
                    except:
                        status = 'No HTTP'

                    findings.append({
                        'subdomain': fqdn,
                        'ip': ip,
                        'http_status': status,
                        'type': 'resolvable',
                        'note': 'Resolves to an IP - possible forgotten DNS',
                    })
                except:
                    pass

        self.results['resolvable_legacy'] = findings
        return findings

    def check_mx_detritus(self):
        findings = []
        try:
            import dns.resolver
            has_dns = True
        except ImportError:
            has_dns = False

        if has_dns:
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    try:
                        mx_ip = socket.gethostbyname(mx_host)
                        findings.append({
                            'mx_host': mx_host,
                            'ip': mx_ip,
                            'priority': rdata.preference,
                        })
                    except:
                        pass
            except:
                pass

        legacy_mx_prefixes = ['mail', 'mail2', 'mail3', 'smtp', 'pop3', 'imap']
        for prefix in legacy_mx_prefixes:
            fqdn = f'{prefix}.{self.domain}'
            try:
                ip = socket.gethostbyname(fqdn)
                findings.append({
                    'mx_host': fqdn,
                    'ip': ip,
                    'type': 'possible_legacy_mx',
                    'note': 'Possible legacy mail server still resolving',
                })
            except:
                pass

        self.results['mx_detritus'] = findings
        return findings

    def check_ns_detritus(self):
        findings = []
        ns_prefixes = ['ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2', 'dns3']
        for prefix in ns_prefixes:
            fqdn = f'{prefix}.{self.domain}'
            try:
                ip = socket.gethostbyname(fqdn)
                findings.append({
                    'nameserver': fqdn,
                    'ip': ip,
                    'type': 'possible_nameserver',
                    'note': 'Nameserver subdomain still resolving',
                })
            except:
                pass
        self.results['ns_detritus'] = findings
        return findings

    def check_www_variants(self):
        findings = []
        variants = [
            f'www.{self.domain}',
            f'ww.{self.domain}',
            f'www2.{self.domain}',
            f'www-{self.domain}',
        ]
        for variant in variants:
            try:
                ip = socket.gethostbyname(variant)
                findings.append({
                    'subdomain': variant,
                    'ip': ip,
                    'type': 'www_variant',
                })
            except:
                pass
        self.results['www_variants'] = findings
        return findings

    def run_all(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, 5)) as executor:
            f1 = executor.submit(self.check_cloudflare_legacy)
            f2 = executor.submit(self.check_non_cloudflare_legacy)
            f3 = executor.submit(self.check_mx_detritus)
            f4 = executor.submit(self.check_ns_detritus)
            f5 = executor.submit(self.check_www_variants)
            concurrent.futures.wait([f1, f2, f3, f4, f5])

        all_findings = []
        for key in ['cloudflare_detritus', 'resolvable_legacy', 'mx_detritus', 'ns_detritus', 'www_variants']:
            items = self.results.get(key, [])
            all_findings.extend(items)

        self.results['total_detritus'] = len(all_findings)
        self.results['all_detritus'] = all_findings

        return self.results
