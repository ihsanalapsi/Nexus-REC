import requests
from urllib.parse import urljoin


class WellKnownRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def discover_wellknown_files(self):
        findings = []
        wellknown_paths = [
            'llms.txt',
            'llms-full.txt',
            'ai.txt',
            'security.txt',
            'robots.txt',
            'sitemap.xml',
            'sitemap_index.xml',
            'keybase.txt',
            'openid-configuration',
            'openid-discovery',
            'change-password',
            'assetlinks.json',
            'apple-app-site-association',
            'app-site-association',
            'google-services.json',
            'google-services.txt',
            'oauth-authorization-server',
            'dnt-policy.txt',
            'gpc.json',
            'mta-sts.txt',
            'pki-validation',
            'nodeinfo',
            'webfinger',
            'host-meta',
            'host-meta.json',
            'reload-config',
            '.well-known/security.txt',
            '.well-known/robots.txt',
            '.well-known/sitemap.xml',
            '.well-known/assetlinks.json',
            '.well-known/apple-app-site-association',
            '.well-known/change-password',
            '.well-known/openid-configuration',
            '.well-known/oauth-authorization-server',
            '.well-known/dnt-policy.txt',
            '.well-known/gpc.json',
            '.well-known/mta-sts.txt',
            '.well-known/keybase.txt',
            '.well-known/nodeinfo',
            '.well-known/webfinger',
            '.well-known/host-meta',
            '.well-known/host-meta.json',
            '.well-known/pki-validation',
            '.well-known/ai.txt',
        ]

        for path in wellknown_paths:
            try:
                url = urljoin(self.target_url, path)
                r = requests.get(url, timeout=8, allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0'})

                if r.status_code in [200, 301, 302]:
                    ct = r.headers.get('Content-Type', '')
                    size = len(r.content)
                    entry = {
                        'path': '/' + path,
                        'status': r.status_code,
                        'size': size,
                        'content_type': ct,
                    }

                    if size < 50000:
                        if 'json' in ct:
                            entry['preview'] = r.text[:500]
                        elif 'xml' in ct:
                            entry['preview'] = r.text[:500]
                        else:
                            entry['preview'] = r.text[:500]

                    if 'llms.txt' in path:
                        entry['category'] = 'llms_intel'
                    elif 'ai.txt' in path:
                        entry['category'] = 'llms_intel'
                    elif 'security.txt' in path or '.well-known/security' in path:
                        entry['category'] = 'security_policy'
                    elif 'robots' in path:
                        entry['category'] = 'crawler_rules'
                    elif 'sitemap' in path:
                        entry['category'] = 'sitemap'
                    elif 'openid' in path or 'oauth' in path:
                        entry['category'] = 'oauth_config'
                    elif 'apple-app-site' in path or 'assetlinks' in path:
                        entry['category'] = 'app_links'
                    elif 'keybase' in path:
                        entry['category'] = 'identity'
                    elif 'change-password' in path:
                        entry['category'] = 'security_policy'
                    else:
                        entry['category'] = 'other'

                    findings.append(entry)
            except:
                pass

        categories = {}
        for f in findings:
            cat = f.get('category', 'other')
            categories.setdefault(cat, []).append(f)

        self.results['wellknown_files'] = findings
        self.results['categories'] = categories

        llms_txt = [f for f in findings if 'llms.txt' in f.get('path', '')]
        if llms_txt:
            self.results['llms_txt_found'] = llms_txt

        security_txt = [f for f in findings if f.get('category') == 'security_policy']
        if security_txt:
            self.results['security_files'] = security_txt

        return findings

    def analyze_llms_txt(self, content):
        info_types = {
            'api_endpoints': [],
            'documentation': [],
            'source_code': [],
            'social_media': [],
            'contact': [],
        }

        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if any(ext in line.lower() for ext in ['.git', 'github.com', 'gitlab', 'bitbucket']):
                info_types['source_code'].append(line)
            elif any(kw in line.lower() for kw in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
                info_types['api_endpoints'].append(line)
            elif any(kw in line.lower() for kw in ['docs.', '/docs/', 'documentation', 'wiki.']):
                info_types['documentation'].append(line)
            elif any(kw in line.lower() for kw in ['twitter', 'linkedin', 'facebook', 'instagram', 't.me']):
                info_types['social_media'].append(line)
            elif any(kw in line.lower() for kw in ['@', 'mailto:', 'contact']):
                info_types['contact'].append(line)

        return info_types

    def run_all(self):
        self.discover_wellknown_files()
        llms = self.results.get('llms_txt_found', [])
        for entry in llms:
            content = entry.get('preview', '')
            if content:
                analysis = self.analyze_llms_txt(content)
                self.results['llms_analysis'] = analysis
        return self.results
