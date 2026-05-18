import requests
import json
import hashlib
import re
from urllib.parse import urljoin


COMMON_MUTATION_NAMES = [
    'signIn', 'login', 'authenticate', 'authorize', 'createSession',
    'startSession', 'generateToken', 'getToken', 'signInWithPassword',
    'passwordSignIn', 'emailSignIn', 'loginUser', 'userLogin',
    'signInUser', 'authenticateUser', 'auth', 'loginWithEmail',
    'tokenAuth', 'registerUser', 'register', 'signUp', 'createUser',
]

COMMON_QUERY_NAMES = [
    'me', 'users', 'user', 'products', 'product', 'orders', 'order',
    'payments', 'payment', 'settings', 'config', 'countries', 'categories',
    'myProduct', 'myProducts', 'myStore', 'myWallet', 'myOrders',
]


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

        # Also try subdomain-based GQL endpoints (api.*.com/graphql)
        domain = self.target_url.split('//')[-1].split('/')[0]
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
            gql_subdomains = [
                f'https://api.{base_domain}/graphql',
                f'https://gql.{base_domain}/graphql',
                f'https://graphql.{base_domain}/graphql',
                f'https://api.{base_domain}/api/graphql',
            ]
            for url in gql_subdomains:
                try:
                    r = requests.post(url,
                        json={'query': '{__typename}'},
                        headers={'Content-Type': 'application/json'},
                        timeout=8)
                    data = r.json()
                    is_gql = 'data' in data or 'errors' in data
                    if is_gql:
                        endpoints.append({
                            'url': url, 'status': r.status_code,
                            'content_type': r.headers.get('Content-Type', ''),
                            'is_graphql': is_gql,
                            'size': len(r.content),
                            'source': 'subdomain_probe',
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
                                    'status': r.status_code,
                                    'body_preview': r.text[:200]}
            except:
                results[url] = {'introspection_enabled': False, 'error': True}
        self.results['introspection'] = results
        return results

    def test_error_based_schema_leak(self):
        """Use error messages to discover schema fields when introspection is disabled."""
        leak_results = {}
        eps = self.results.get('endpoints', [])
        for ep in eps:
            url = ep['url']
            if not ep.get('is_graphql', False):
                continue

            discovered_queries = []
            discovered_mutations = []
            discovered_types = {}

            # Try common queries to trigger field suggestions
            for qname in COMMON_QUERY_NAMES:
                try:
                    r = requests.post(url,
                        json={'query': f'{{{qname}{{id}}}}'},
                        headers={'Content-Type': 'application/json',
                                 'Origin': self.target_url},
                        timeout=10)
                    data = r.json()
                    if 'errors' in data:
                        err = data['errors'][0]['message']
                        # "Cannot query field" reveals the type/field name
                        # "Did you mean" reveals field suggestions
                        if 'Cannot query field' in err:
                            query_type = re.search(r'field "(\w+)" on type "(\w+)"', err)
                            if query_type:
                                discovered_queries.append({
                                    'name': qname,
                                    'error': err,
                                    'suggestion': query_type.group(1),
                                    'type': query_type.group(2),
                                })
                        elif 'Unauthorized' in err:
                            discovered_queries.append({
                                'name': qname,
                                'requires_auth': True,
                            })
                        elif 'is required' in err:
                            discovered_queries.append({
                                'name': qname,
                                'requires_args': True,
                                'error': err,
                            })
                    else:
                        discovered_queries.append({
                            'name': qname,
                            'public': True,
                        })
                except:
                    pass

            # Try common mutations
            for mname in COMMON_MUTATION_NAMES:
                try:
                    r = requests.post(url,
                        json={'query': f'mutation{{{mname}(email:"test" password:"test"){{id}}}}'},
                        headers={'Content-Type': 'application/json',
                                 'Origin': self.target_url},
                        timeout=10)
                    data = r.json()
                    if 'errors' in data:
                        err = data['errors'][0]['message']
                        if 'Cannot query field' in err:
                            pass  # mutation doesn't exist
                        elif 'Unauthorized' in err:
                            discovered_mutations.append({
                                'name': mname,
                                'requires_auth': True,
                            })
                        elif 'is required' in err or 'Unknown argument' in err:
                            discovered_mutations.append({
                                'name': mname,
                                'exists': True,
                                'error': err,
                            })
                        else:
                            discovered_mutations.append({
                                'name': mname,
                                'exists': True,
                                'error': err,
                            })
                    else:
                        discovered_mutations.append({
                            'name': mname,
                            'public': True,
                        })
                except:
                    pass

            if discovered_queries or discovered_mutations:
                leak_results[url] = {
                    'queries_discovered': discovered_queries[:30],
                    'mutations_discovered': discovered_mutations[:30],
                }

        self.results['error_schema_leak'] = leak_results
        return leak_results

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

    def test_csrf_protection(self):
        """Test if CSRF protection (apollo-require-preflight) is active."""
        csrf_results = {}
        eps = self.results.get('endpoints', [])
        for ep in eps:
            url = ep['url']
            if not ep.get('is_graphql', False):
                continue

            tests = {
                'json_no_origin': requests.post(url,
                    json={'query': '{__typename}'},
                    headers={'Content-Type': 'application/json'},
                    timeout=10),
                'json_with_origin': requests.post(url,
                    json={'query': '{__typename}'},
                    headers={'Content-Type': 'application/json',
                             'Origin': self.target_url},
                    timeout=10),
                'form_urlencoded': requests.post(url,
                    data={'query': '{__typename}'},
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=10),
            }

            csrf_findings = {}
            for test_name, response in tests.items():
                try:
                    data = response.json()
                    csrf_findings[test_name] = {
                        'status': response.status_code,
                        'blocked': 'CSRF' in str(data) or 'csrf' in str(data).lower(),
                        'response': str(data)[:200],
                    }
                except:
                    csrf_findings[test_name] = {
                        'status': response.status_code,
                        'blocked': True,
                        'response': response.text[:200],
                    }

            csrf_results[url] = csrf_findings
        self.results['csrf_protection'] = csrf_results
        return csrf_results

    def test_appsync_endpoints(self):
        appsync_findings = {}
        eps = self.results.get('endpoints', [])
        for ep in eps:
            url = ep['url']
            if not ep.get('is_graphql', False):
                continue

            tests = []
            api_key_pattern = r'(da2-[a-zA-Z0-9]+)'
            api_keys = re.findall(api_key_pattern, str(ep))

            for method in ['POST', 'GET', 'OPTIONS']:
                try:
                    r = requests.request(method, url,
                        json={'query': '{__typename}'} if method != 'GET' else None,
                        headers={'Content-Type': 'application/json'},
                        timeout=10)
                    data = r.json() if r.text else {}
                    response_text = r.text
                    is_appsync = any(k in response_text for k in
                        ['UnknownOperationException', 'UnauthorizedException',
                         'UnsupportedOperationException'])
                    tests.append({
                        'method': method,
                        'status': r.status_code,
                        'is_appsync': is_appsync,
                    })
                except:
                    pass

            api_key_tests = []
            for key in api_keys[:5]:
                try:
                    r = requests.post(url,
                        json={'query': '{__typename}'},
                        headers={'Content-Type': 'application/json',
                                 'x-api-key': key},
                        timeout=10)
                    data = r.json() if r.text else {}
                    api_key_tests.append({
                        'api_key': key[:15] + '...',
                        'status': r.status_code,
                        'authenticated': 'data' in data and data['data'] is not None,
                    })
                except:
                    pass

            url_ep = ep
            auth_headers_test = {}
            for auth_header, value in [
                ('Authorization', 'AWS4-HMAC-SHA256 ...'),
                ('x-api-key', 'test'),
            ]:
                try:
                    r = requests.post(url,
                        json={'query': '{__typename}'},
                        headers={'Content-Type': 'application/json',
                                 auth_header: value.split(' ')[0] if ' ' in value else value},
                        timeout=10)
                    data = r.json() if r.text else {}
                    auth_headers_test[auth_header] = {
                        'status': r.status_code,
                        'error_type': data.get('errors', [{}])[0].get('errorType', '') if data.get('errors') else 'none',
                    }
                except:
                    pass

            if any(t.get('is_appsync') for t in tests) or api_key_tests or auth_headers_test:
                appsync_findings[url] = {
                    'tests': tests,
                    'api_key_results': api_key_tests,
                    'auth_header_results': auth_headers_test,
                    'detected_api_keys': api_keys,
                }

        if appsync_findings:
            self.results['appsync_endpoints'] = appsync_findings
        return appsync_findings

    def run_all(self):
        self.find_endpoints()
        self.test_introspection()
        self.test_error_based_schema_leak()
        self.test_batch_queries()
        self.test_csrf_protection()
        self.test_appsync_endpoints()
        return self.results
