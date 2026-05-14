import requests
import json
import hashlib
from urllib.parse import urljoin

class GraphQLRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
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

    def find_endpoints(self):
        self._fetch_homepage()
        common_paths = [
            '/graphql', '/query', '/graphiql', '/playground',
            '/graphql/explore', '/graphql/schema', '/api/graphql',
            '/api/query', '/v1/graphql', '/v2/graphql',
            '/graphql/v1', '/graphql/v2', '/gql',
            '/graphql.json', '/schema.json', '/graphql/schema.json',
        ]
        endpoints = []
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                r = requests.get(url, timeout=8,
                    headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code != 404:
                    if self._is_spa_catchall(r):
                        continue
                    ct = r.headers.get('Content-Type', '')
                    body_lower = r.text.lower()
                    is_graphql = any(k in ct.lower() or k in body_lower
                                     for k in ['graphql', 'schema', 'type',
                                                'query', 'mutation'])
                    endpoints.append({
                        'url': url, 'status': r.status_code,
                        'content_type': ct,
                        'is_graphql': is_graphql,
                        'size': len(r.content),
                    })
            except:
                pass
        self.results['endpoints'] = endpoints
        return endpoints

    def test_introspection(self):
        introspection_query = {
            'query': '''
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  kind name description
                  fields {
                    name description
                    args { name description type { kind name ofType { kind name } } }
                    type { kind name ofType { kind name ofType { kind name } } }
                  }
                }
                directives { name description locations }
              }
            }
            '''
        }
        results = {}
        eps = self.results.get('endpoints', [])
        for ep in eps:
            url = ep['url']
            if not ep.get('is_graphql', False):
                continue
            try:
                r = requests.post(url, json=introspection_query, timeout=15,
                    headers={'Content-Type': 'application/json'})
                if r.status_code == 200:
                    data = r.json()
                    if 'data' in data and '__schema' in data['data']:
                        schema = data['data']['__schema']
                        types = schema.get('types', [])
                        sensitive_types = [t for t in types if any(
                            kw in (t.get('name', '') or '').lower()
                            for kw in ['user', 'auth', 'token', 'key',
                                       'secret', 'admin', 'internal',
                                       'password', 'credential', 'payment',
                                       'order', 'address', 'phone'])]
                        mutations = schema.get('mutationType', {})
                        results[url] = {
                            'introspection_enabled': True,
                            'total_types': len(types),
                            'query_type': schema.get('queryType', {}),
                            'mutation_type': mutations,
                            'sensitive_types': [
                                {'name': t['name'], 'kind': t['kind'],
                                 'fields': len(t.get('fields', []))}
                                for t in sensitive_types
                            ],
                            'sensitive_count': len(sensitive_types),
                        }
                    else:
                        results[url] = {'introspection_enabled': False}
                else:
                    results[url] = {'introspection_enabled': False,
                                    'status': r.status_code}
            except:
                results[url] = {'introspection_enabled': False, 'error': True}
        self.results['introspection'] = results
        return results

    def test_batch_queries(self):
        batch_results = {}
        eps = self.results.get('endpoints', [])
        for ep in eps:
            url = ep['url']
            if not ep.get('is_graphql', False):
                continue
            try:
                payload = [
                    {'query': '{ __typename }'},
                    {'query': '{ __typename }'},
                    {'query': '{ __typename }'},
                ]
                r = requests.post(url, json=payload, timeout=10,
                    headers={'Content-Type': 'application/json'})
                if r.status_code == 200:
                    batch_results[url] = {
                        'batch_allowed': True,
                        'response': r.json()[:2]
                    }
                else:
                    batch_results[url] = {'batch_allowed': False}
            except:
                batch_results[url] = {'batch_allowed': False, 'error': True}
        self.results['batch_queries'] = batch_results
        return batch_results

    def run_all(self):
        self.find_endpoints()
        self.test_introspection()
        self.test_batch_queries()
        return self.results
