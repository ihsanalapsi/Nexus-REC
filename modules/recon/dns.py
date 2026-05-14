import requests
import socket
import re
import concurrent.futures
import subprocess


class DNSRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def detect_wildcard_dns(self):
        findings = {
            'wildcard_detected': False,
            'test_subdomains': [],
            'base_ip': None,
        }
        try:
            base_ip = socket.gethostbyname(self.domain)
            findings['base_ip'] = base_ip

            test_subs = [
                'thisisrandomxyz123', 'nonexistenttestabc',
                'wildcardcheck987', 'doesnotexist555',
                'randomtestxyz789', 'invalidsubdomain321',
            ]
            matches = 0
            for sub in test_subs:
                fqdn = f"{sub}.{self.domain}"
                try:
                    ip = socket.gethostbyname(fqdn)
                    findings['test_subdomains'].append({
                        'subdomain': fqdn,
                        'ip': ip,
                        'matches_base': ip == base_ip,
                    })
                    if ip == base_ip:
                        matches += 1
                except:
                    pass

            wildcard_ratio = matches / len(test_subs) if test_subs else 0
            findings['wildcard_detected'] = wildcard_ratio > 0.3
            findings['confidence'] = 'HIGH' if wildcard_ratio > 0.6 else 'MEDIUM' if wildcard_ratio > 0.3 else 'LOW'
            findings['total_matched'] = matches
            findings['total_tested'] = len(test_subs)
            if findings['wildcard_detected']:
                findings['note'] = 'Domain uses wildcard DNS (*.{domain}) - all subdomains resolve to same IP'
        except:
            pass
        self.results['wildcard_dns'] = findings
        return findings

    def analyze_ssl_cert(self):
        findings = {}
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.domain}:443', '-servername', self.domain],
                input=b'QUIT\n', capture_output=True, timeout=10
            )
            output = result.stdout.decode() + result.stderr.decode()

            subject = re.search(r'subject=(.*)', output)
            if subject:
                findings['subject'] = subject.group(1).strip()

            issuer = re.search(r'issuer=(.*)', output)
            if issuer:
                findings['issuer'] = issuer.group(1).strip()

            not_before = re.search(r'NotBefore: (.*?)(?:\n|GMT)', output)
            if not_before:
                findings['not_before'] = not_before.group(1).strip() + ' GMT'

            not_after = re.search(r'NotAfter : (.*?)(?:\n|GMT)', output)
            if not not_after:
                not_after = re.search(r'NotAfter: (.*?)(?:\n|GMT)', output)
            if not_after:
                findings['not_after'] = not_after.group(1).strip() + ' GMT'

            sans = re.findall(r'DNS:([a-zA-Z0-9.*-]+)', output)
            if sans:
                findings['subject_alt_names'] = list(set(sans))
                findings['is_wildcard'] = any('*' in san for san in sans)
                findings['covers_self'] = self.domain in findings['subject_alt_names'] or f"*.{'.'.join(self.domain.split('.')[1:])}" in findings['subject_alt_names']

            pubkey = re.search(r'Server public key is (\d+) bit', output)
            if pubkey:
                findings['public_key_bits'] = int(pubkey.group(1))

            proto = re.search(r'New, (TLSv[0-9.]+)', output)
            if proto:
                findings['tls_version'] = proto.group(1)

            self.results['ssl_cert'] = findings
        except Exception as e:
            self.results['ssl_cert'] = {'error': str(e)}
        return findings

    def scan_common_ports(self):
        findings = []
        ports = [22, 80, 443, 8080, 8443, 3000, 5000, 8000, 9090,
                 3306, 5432, 6379, 27017, 1433, 1521,
                 21, 25, 53, 110, 143, 993, 995, 587, 465]

        try:
            ip = socket.gethostbyname(self.domain)

            def _check_port(port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = 'unknown'
                        return {'port': port, 'protocol': 'tcp', 'service': service}
                except:
                    pass
                finally:
                    sock.close()
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                futures = [ex.submit(_check_port, p) for p in ports]
                for f in concurrent.futures.as_completed(futures):
                    r = f.result()
                    if r:
                        findings.append(r)
            findings.sort(key=lambda x: x['port'])
            self.results['open_ports'] = findings
            self.results['port_count'] = len(findings)
        except:
            self.results['open_ports'] = []
        return findings

    def check_reverse_dns(self):
        findings = {}
        try:
            ip = socket.gethostbyname(self.domain)
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                findings['reverse_dns'] = hostname
                findings['aliases'] = aliases
            except:
                findings['reverse_dns'] = 'N/A'
            findings['ip'] = ip
        except:
            pass
        self.results['reverse_dns'] = findings
        return findings

    def check_name_servers(self):
        findings = {}
        try:
            result = subprocess.run(
                ['nslookup', '-type=NS', self.domain],
                capture_output=True, timeout=10, text=True
            )
            ns_servers = re.findall(r'nameserver\s*=\s*(\S+)', result.stdout.lower())
            if not ns_servers:
                ns_servers = re.findall(r'nameserver\s+(\S+)', result.stdout)
            if ns_servers:
                findings['name_servers'] = list(set(ns_servers))
        except:
            pass
        self.results['name_servers'] = findings
        return findings

    def check_subdomain_ssl_validity(self):
        findings = {}
        try:
            base_cert_result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.domain}:443', '-servername', self.domain],
                input=b'QUIT\n', capture_output=True, timeout=10
            )
            base_output = (base_cert_result.stdout + base_cert_result.stderr).decode()
            base_sans = [f'*.{self.domain}', self.domain]
            sans_found = re.findall(r'DNS:([a-zA-Z0-9.*-]+)', base_output)
            if sans_found:
                base_sans = sans_found

            test_subs = ['www', 'api', 'admin', 'dev']
            subdomain_results = []
            for sub in test_subs:
                fqdn = f"{sub}.{self.domain}"
                try:
                    http_result = requests.get(f'https://{fqdn}', timeout=5, verify=False,
                        headers={'User-Agent': 'Mozilla/5.0'})
                    subdomain_results.append({
                        'subdomain': fqdn,
                        'ssl_valid': True,
                        'http_status': http_result.status_code,
                    })
                except requests.exceptions.SSLError as e:
                    err_str = str(e).lower()
                    if 'unrecognized name' in err_str:
                        subdomain_results.append({
                            'subdomain': fqdn,
                            'ssl_valid': False,
                            'reason': 'SSL: unrecognized name (not in cert SAN)',
                        })
                    elif 'certificate verify failed' in err_str:
                        subdomain_results.append({
                            'subdomain': fqdn,
                            'ssl_valid': False,
                            'reason': 'SSL: certificate verify failed',
                        })
                    else:
                        subdomain_results.append({
                            'subdomain': fqdn,
                            'ssl_valid': False,
                            'reason': str(e)[:100],
                        })
                except:
                    subdomain_results.append({
                        'subdomain': fqdn,
                        'ssl_valid': False,
                        'reason': 'Connection failed',
                    })

            findings['base_sans'] = base_sans
            findings['subdomain_tests'] = subdomain_results
            findings['subdomains_not_covered'] = [s for s in subdomain_results if not s.get('ssl_valid')]
        except:
            pass
        self.results['subdomain_ssl'] = findings
        return findings

    def run_all(self):
        self.detect_wildcard_dns()
        self.analyze_ssl_cert()
        self.scan_common_ports()
        self.check_reverse_dns()
        self.check_name_servers()
        self.check_subdomain_ssl_validity()
        return self.results
