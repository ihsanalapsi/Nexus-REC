import requests


class BackendScanRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.backends = []

    def set_backends(self, backends, domain=None):
        self.backends = backends or []
        if domain:
            self.domain = domain

    def _real_backends(self):
        blocked_terms = ['google', 'w3.org', 'apple.com', 'cloudflare', 'react.dev']
        real = []
        for backend in self.backends:
            url = backend.get('url', '') if isinstance(backend, dict) else str(backend)
            if not url:
                continue
            if self.domain in url:
                continue
            if any(term in url for term in blocked_terms):
                continue
            real.append({'url': url})
        return real

    def _scan_backend(self, backend_url):
        result = {'url': backend_url}
        try:
            response = requests.get(
                backend_url,
                timeout=8,
                headers={'User-Agent': 'Mozilla/5.0'},
            )
            result.update({
                'status': response.status_code,
                'size': len(response.content),
                'server': response.headers.get('Server', ''),
                'content_type': response.headers.get('Content-Type', ''),
            })
            if 'text/html' not in result.get('content_type', ''):
                result['preview'] = response.text[:300]

            for api_path in ['/api/', '/health', '/status', '/graphql', '/docs']:
                try:
                    api_response = requests.get(
                        f"{backend_url.rstrip('/')}{api_path}",
                        timeout=5,
                        headers={'User-Agent': 'Mozilla/5.0'},
                    )
                    if api_response.status_code not in [404, 405]:
                        result.setdefault('api_endpoints', []).append({
                            'path': api_path,
                            'status': api_response.status_code,
                            'size': len(api_response.content),
                        })
                except Exception:
                    pass
        except Exception as exc:
            result['error'] = str(exc)
        return result

    def run_all(self):
        self.results = {}
        real_backends = self._real_backends()
        self.results['backend_count'] = len(real_backends)
        self.results['scanned_backends'] = {}
        for backend in real_backends[:3]:
            url = backend.get('url', '')
            self.results['scanned_backends'][url] = self._scan_backend(url)
        return self.results
