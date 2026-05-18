import requests
import re

class CloudRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def check_s3_buckets(self):
        bucket_variations = [
            self.domain, self.domain.replace('.', '-'), self.domain.replace('.', ''),
            f"{self.domain}-assets", f"{self.domain}-images", f"{self.domain}-media",
            f"{self.domain}-static", f"{self.domain}-cdn", f"{self.domain}-uploads",
            f"{self.domain}-backup", f"{self.domain}-data", f"{self.domain}-files",
            f"{self.domain}-public", f"{self.domain}-dev", f"{self.domain}-staging",
            f"{self.domain}-prod", f"{self.domain}-test",
            self.domain.split('.')[0],
            f"{self.domain.split('.')[0]}-assets",
            f"{self.domain.split('.')[0]}-images",
        ]
        regions = ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1']
        buckets = []
        for name in bucket_variations[:20]:
            for region in regions[:2]:
                url = f"https://{name}.s3.{region}.amazonaws.com"
                try:
                    r = requests.get(url, timeout=5)
                    if r.status_code not in [404, 403]:
                        is_public = 'ListBucketResult' in r.text
                        buckets.append({
                            'bucket': name, 'region': region,
                            'url': url, 'status': r.status_code,
                            'public': is_public,
                            'response_preview': r.text[:200]
                        })
                except:
                    pass
        self.results['s3_buckets'] = buckets
        return buckets

    def check_cloudfront(self):
        cf_indicators = {
            'x-amz-cf-id': 'CloudFront Distribution ID',
            'x-amz-cf-pop': 'CloudFront POP',
            'x-cache': 'CloudFront Cache',
            'via': 'CloudFront Via',
            'x-amz-cf': 'CloudFront',
        }
        detected = {}
        try:
            r = requests.get(self.target_url, timeout=10)
            hdrs = str(r.headers).lower()
            for indicator, label in cf_indicators.items():
                if indicator in hdrs:
                    for key, val in r.headers.items():
                        if indicator.lower() in key.lower():
                            detected[indicator] = val
            self.results['cloudfront'] = {
                'detected': len(detected) > 0,
                'headers': detected
            }
        except:
            self.results['cloudfront'] = {'detected': False}
        return self.results

    def check_cache_poisoning(self):
        findings = []
        try:
            headers = {
                'X-Forwarded-Host': 'evil.com',
                'X-Forwarded-Scheme': 'https',
                'X-Original-URL': '/admin',
                'X-Rewrite-URL': '/admin',
            }
            r = requests.get(self.target_url, headers=headers, timeout=10)
            if 'evil.com' in r.text:
                findings.append('Cache Poisoning: X-Forwarded-Host reflected in response')
            if r.headers.get('X-Cache') == 'HIT':
                findings.append('Cache Poisoning Potential: Response is cached')

            r2 = requests.get(self.target_url, timeout=10)
            if 'Access-Control-Allow-Origin' in r2.headers:
                origin = r2.headers['Access-Control-Allow-Origin']
                if origin == '*':
                    findings.append('CORS Misconfiguration: Wildcard origin allowed')
                elif 'evil' in origin:
                    findings.append('CORS Misconfiguration: Origin reflected')
        except:
            pass
        self.results['cache_poisoning'] = findings
        return findings

    def check_azure_blob(self):
        candidates = [
            f"{self.domain.replace('.', '')}",
            f"{self.domain.split('.')[0]}",
            f"{self.domain.replace('.', '-')}",
        ]
        found = []
        for c in candidates:
            for suffix in ['', '-assets', '-media', '-static', '-public']:
                url = f"https://{c}{suffix}.blob.core.windows.net"
                try:
                    r = requests.get(url, timeout=5)
                    if r.status_code not in [404, 400]:
                        found.append({'url': url, 'status': r.status_code})
                except:
                    pass
        self.results['azure_blob'] = found
        return found

    def detect_netscaler(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            set_cookie = str(r.headers.get('Set-Cookie', ''))
            if 'NSC_' in set_cookie:
                findings['netscaler_detected'] = True
                findings['source'] = 'Set-Cookie: NSC_* — Citrix ADC/NetScaler'
            x_via = r.headers.get('X-Via-NSCOPI', '')
            if x_via:
                findings['netscaler_x_via'] = x_via
        except:
            pass
        self.results['netscaler'] = findings
        return findings

    def detect_cloudflare_subdomains(self):
        cf_ranges = [
            '188.114.96.0/20', '188.114.97.0/20',
            '173.245.48.0/20', '103.21.244.0/22',
            '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17',
            '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13',
            '131.0.72.0/22',
        ]
        cf_start_octets = {'188.114', '173.245', '103.21', '103.22', '103.31',
                           '141.101', '108.162', '190.93', '197.234', '198.41',
                           '162.158', '104.16', '104.24', '172.64', '131.0'}
        findings = []
        try:
            import socket
            for prefix in ['cdn', 'download', 'static', 'assets', 'media',
                           'img', 'css', 'js', 'files', 'upload']:
                fqdn = f"{prefix}.{self.domain}"
                try:
                    ips = socket.gethostbyname_ex(fqdn)[2]
                    for ip in ips:
                        ip_start = '.'.join(ip.split('.')[:2])
                        if ip_start in cf_start_octets:
                            findings.append({
                                'subdomain': fqdn,
                                'ip': ip,
                                'service': 'Cloudflare',
                                'note': 'Cloudflare-protected subdomain (legacy/backup)',
                            })
                            break
                except:
                    pass
        except:
            pass
        self.results['cloudflare_subdomains'] = findings
        return findings

    def run_all(self):
        self.check_cloudfront()
        self.check_s3_buckets()
        self.check_azure_blob()
        self.check_cache_poisoning()
        self.detect_cloudflare_subdomains()
        self.detect_netscaler()
        return self.results
