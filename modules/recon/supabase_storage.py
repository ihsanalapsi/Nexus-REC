import requests
import json
import re


class SupabaseStorageRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}

    def find_supabase_refs(self):
        findings = {}
        try:
            r = requests.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text
            csp = r.headers.get('Content-Security-Policy', '')

            refs = re.findall(r'(https?://[a-zA-Z0-9-]+\.supabase\.co)', html + csp)
            if refs:
                ref = refs[0]
                m = re.search(r'https?://([a-zA-Z0-9-]+)\.supabase\.co', ref)
                if m:
                    findings['project_ref'] = m.group(1)
                    findings['storage_url'] = f'https://{m.group(1)}.supabase.co/storage/v1/'

            anon_key = re.search(
                r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
                html
            )
            if anon_key:
                findings['anon_key'] = anon_key.group(1)
        except:
            pass
        self.results['project'] = findings
        return findings

    def enumerate_buckets(self):
        findings = []
        project_info = self.results.get('project', {})
        storage_url = project_info.get('storage_url', '')
        anon_key = project_info.get('anon_key', '')

        if not storage_url or not anon_key:
            self.results['buckets'] = findings
            return findings

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
        }

        try:
            url = storage_url + 'bucket'
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                try:
                    buckets = r.json()
                    for bucket in buckets:
                        bucket_info = {
                            'id': bucket.get('id', 'unknown'),
                            'name': bucket.get('name', 'unknown'),
                            'public': bucket.get('public', False),
                            'owner': bucket.get('owner', 'unknown'),
                            'created_at': bucket.get('created_at', ''),
                            'url': f"{storage_url}bucket/{bucket.get('id', '')}",
                        }

                        if bucket.get('public'):
                            bucket_info['listing_url'] = storage_url + 'object/list/' + bucket.get('id', '')
                            try:
                                r2 = requests.post(
                                    bucket_info['listing_url'],
                                    headers=headers,
                                    json={'prefix': '', 'limit': 100},
                                    timeout=10
                                )
                                if r2.status_code == 200:
                                    objects = r2.json()
                                    bucket_info['objects'] = objects
                                    bucket_info['object_count'] = len(objects) if isinstance(objects, list) else 0
                                    if isinstance(objects, list) and objects:
                                        bucket_info['sample_objects'] = objects[:10]
                            except:
                                pass

                            for obj in bucket_info.get('objects', []):
                                if isinstance(obj, dict) and 'name' in obj:
                                    obj_name = obj['name']
                                    obj_url = f"{storage_url}object/public/{bucket['id']}/{obj_name}"
                                    bucket_info.setdefault('public_urls', []).append(obj_url)

                        findings.append(bucket_info)
                except:
                    pass
            elif r.status_code == 401:
                self.results['storage_error'] = 'Unauthorized - cannot list buckets'
        except:
            pass

        self.results['buckets'] = findings
        public_buckets = [b for b in findings if b.get('public')]
        if public_buckets:
            self.results['public_buckets'] = public_buckets

        return findings

    def try_common_buckets(self):
        findings = []
        project_info = self.results.get('project', {})
        storage_url = project_info.get('storage_url', '')
        anon_key = project_info.get('anon_key', '')

        if not storage_url or not anon_key:
            self.results['common_buckets'] = findings
            return findings

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
        }

        common_bucket_names = [
            'public', 'private', 'uploads', 'images', 'media',
            'files', 'assets', 'static', 'avatars', 'profiles',
            'products', 'documents', 'backups', 'exports',
            'temp', 'tmp', 'staging', 'test', 'dev',
        ]

        for bucket_name in common_bucket_names:
            try:
                url = storage_url + 'object/list/' + bucket_name
                r = requests.post(url, headers=headers,
                    json={'prefix': '', 'limit': 10}, timeout=8)
                if r.status_code == 200:
                    try:
                        objects = r.json()
                        if isinstance(objects, list) and objects:
                            findings.append({
                                'bucket': bucket_name,
                                'accessible': True,
                                'object_count': len(objects),
                                'sample': objects[:5],
                                'public_base_url': f"{storage_url}object/public/{bucket_name}/",
                            })
                    except:
                        pass
            except:
                pass

        self.results['common_buckets'] = findings
        return findings

    def run_all(self):
        self.find_supabase_refs()
        self.enumerate_buckets()
        self.try_common_buckets()
        return self.results
