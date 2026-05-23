import requests
import re
import base64
import json
import hmac
import hashlib
import urllib.parse


class CookieRecon:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self._session = requests.Session()

    def analyze_cookies(self):
        findings = {
            'total_cookies': 0,
            'cookies': [],
            'missing_secure': [],
            'missing_httponly': [],
            'potential_jwt': [],
            'credential_leak': [],
            'csrf_analysis': {},
        }
        try:
            r = self._session.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            set_cookie = r.headers.get('Set-Cookie', '')
            if not set_cookie:
                self.results['cookies'] = findings
                return findings

            raw_cookies = r.headers.get_all('Set-Cookie') if hasattr(r.headers, 'get_all') else [set_cookie]
            if not raw_cookies:
                raw_cookies = [set_cookie]

            parsed = []
            for header in raw_cookies:
                parts = header.split(';')
                name_value = parts[0].strip()
                if '=' not in name_value:
                    continue
                name, value = name_value.split('=', 1)
                name = name.strip()
                value = value.strip()
                flags = [p.strip() for p in parts[1:]]

                entry = {
                    'name': name,
                    'value_preview': value[:80] + '...' if len(value) > 80 else value,
                    'value_length': len(value),
                    'secure': 'Secure' in flags,
                    'httponly': 'HttpOnly' in flags,
                    'samesite': None,
                    'path': None,
                    'max_age': None,
                }
                for f in flags:
                    if f.lower().startswith('samesite='):
                        entry['samesite'] = f.split('=', 1)[1]
                    elif f.lower().startswith('path='):
                        entry['path'] = f.split('=', 1)[1]
                    elif f.lower().startswith('max-age='):
                        entry['max_age'] = f.split('=', 1)[1]

                if not entry['secure']:
                    findings['missing_secure'].append(name)
                if not entry['httponly']:
                    findings['missing_httponly'].append(name)

                self._check_jwt_cookie(name, value, findings)
                self._check_credential_leak(name, value, findings)
                parsed.append(entry)

            findings['cookies'] = parsed
            findings['total_cookies'] = len(parsed)
        except:
            pass
        if findings.get('potential_jwt'):
            self._analyze_jwt_tokens(findings)
        self.results['cookies'] = findings
        return findings

    def _check_jwt_cookie(self, name, value, findings):
        decoded = urllib.parse.unquote(value)
        pattern = r'([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)'
        matches = re.findall(pattern, decoded)
        for header_b64, payload_b64, sig in matches:
            try:
                padded_h = header_b64 + '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else header_b64
                header = base64.urlsafe_b64decode(padded_h)
                header_json = json.loads(header)
                if header_json.get('typ') == 'JWT' or header_json.get('alg'):
                    padded_p = payload_b64 + '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else payload_b64
                    payload = base64.urlsafe_b64decode(padded_p)
                    payload_json = json.loads(payload)
                    raw_token = f"{header_b64}.{payload_b64}.{sig}"
                    cracked_secret = self._crack_jwt_hs256(raw_token)
                    entry = {
                        'cookie_name': name,
                        'header': header_json,
                        'payload': payload_json,
                        'header_b64': header_b64,
                        'payload_b64': payload_b64,
                        'signature': sig[:20] + '...',
                        'signature_full': sig,
                        '_raw_token': raw_token,
                        'has_user_pass': 'user' in payload_json or 'pass' in payload_json or 'password' in payload_json or 'username' in payload_json,
                        'has_cred_fields': any(k in payload_json for k in ['user', 'pass', 'password', 'username', 'token', 'secret', 'key', 'email']),
                    }

                    # Role & permission analysis
                    self._analyze_jwt_roles(payload_json, findings, entry)

                    if cracked_secret:
                        entry['hs256_cracked'] = True
                        entry['hs256_secret'] = cracked_secret
                    findings['potential_jwt'].append(entry)
                    if any(k in payload_json for k in ['user', 'pass', 'password', 'username']):
                        findings['credential_leak'].append({
                            'cookie_name': name,
                            'type': 'JWT credential in cookie payload',
                            'decoded_payload_preview': {k: v for k, v in list(payload_json.items())[:6]},
                            'cracked_secret': cracked_secret,
                        })
            except:
                pass

    def _check_credential_leak(self, name, value, findings):
        decoded = urllib.parse.unquote(value)
        if 'user' in name.lower() or 'username' in name.lower() or 'email' in name.lower():
            findings['credential_leak'].append({
                'cookie_name': name,
                'type': 'Potential username stored in cookie name',
            })
        for key in ['password', 'pass', 'secret', 'token', 'cred', 'auth']:
            if key in name.lower():
                findings['credential_leak'].append({
                    'cookie_name': name,
                    'type': f'Sensitive keyword in cookie name: {key}',
                })

        try:
            value_decoded = urllib.parse.unquote(value)
            for secret_key in ['"user"', '"pass"', '"password"', '"username"', '"secret"', '"token"', '"email"']:
                if secret_key in value_decoded:
                    findings['credential_leak'].append({
                        'cookie_name': name,
                        'type': f'JSON credential field found in cookie value: {secret_key}',
                        'value_preview': value_decoded[:100],
                    })
                    break
        except:
            pass

    def _analyze_jwt_roles(self, payload, findings, entry):
        """Analyze JWT payload for role and permission claims."""
        # Role claims: check multiple naming conventions
        role_keys = [
            'role', 'roles', 'Role', 'permission', 'permissions',
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/roles',
            'is_admin', 'isAdmin', 'is_superuser', 'isSuperuser',
            'access_level', 'accessLevel', 'user_type', 'userType',
        ]
        found_roles = {}
        for key in role_keys:
            if key in payload:
                found_roles[key] = payload[key]

        if found_roles:
            role_analysis = {'claims_found': found_roles}
            val = str(list(found_roles.values())[0]).lower()
            elevated = any(r in val for r in ['admin', 'super', 'owner', 'root', 'manager'])
            role_analysis['has_elevated_role'] = elevated

            # Check for elevation risk
            if elevated:
                role_analysis['risk'] = 'JWT contains elevated role claim'
                # Check if SMS/phone was confirmed (weak registration)
                phone_confirmed = payload.get(
                    'phone_number_confirmed',
                    payload.get('phoneNumberConfirmed', payload.get('phone_confirmed', 'unknown'))
                )
                if phone_confirmed == False or phone_confirmed == 'false' or phone_confirmed is False:
                    role_analysis['phone_confirmed'] = False
                    role_analysis[
                        'vulnerability'
                    ] = "Elevated role with unconfirmed phone — possible no-OTP registration bypass"
                    entry['role_vulnerability'] = role_analysis['vulnerability']

            entry['role_analysis'] = role_analysis
            findings.setdefault('role_analysis', []).append(role_analysis)

    COMMON_JWT_SECRETS = [
        'secret', 'supersecret', 'password', '123456', 'admin',
        'changeme', 'secretkey', 'secret123', 'key', 'token',
        'jwt_secret', 'jwt', 'node', 'express', 'nextjs',
        'laravel', 'django', 'flask', 'rails', 'pass',
        'test', 'dev', 'staging', 'production', 'prod',
        'debug', 'default', 'insecure', 'weak', 'qwerty',
        'abc123', 'letmein', 'monkey', 'dragon', 'master',
        'access', 'private', 'public', 'auth', 'bearer',
        'xsrf', 'csrf', 'session', 'cookie', 'api_key',
        'supabase', 'firebase', 'stripe', 'paypal',
    ]

    def _crack_jwt_hs256(self, jwt_token):
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig = parts
        msg = f"{header_b64}.{payload_b64}".encode()
        for secret in self.COMMON_JWT_SECRETS:
            try:
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                ).rstrip(b'=').decode()
                if expected == sig:
                    return secret
            except Exception:
                pass
        return None

    def _analyze_jwt_tokens(self, findings):
        for j in findings.get('potential_jwt', []):
            token_str = f"{j.get('header_b64','')}.{j.get('payload_b64','')}.{j.get('signature','')}"
            full_token = j.get('_raw_token', '')
            cracked = self._crack_jwt_hs256(full_token or token_str)
            if cracked:
                j['hs256_cracked'] = True
                j['hs256_secret'] = cracked

    def analyze_csrf(self):
        findings = {}
        try:
            r = self._session.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            html = r.text
            csrf_meta = re.findall(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', html, re.IGNORECASE)
            csrf_hidden = re.findall(r'<input[^>]*name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']', html, re.IGNORECASE)
            csrf_cookie = 'csrf' in str(r.headers.get('Set-Cookie', '')).lower() or '_csrf' in str(r.cookies.keys())
            findings = {
                'csrf_in_meta': bool(csrf_meta),
                'csrf_in_form': bool(csrf_hidden),
                'csrf_in_cookie': csrf_cookie,
                'csrf_token_preview': (csrf_meta[0] if csrf_meta else csrf_hidden[0] if csrf_hidden else None)[:30] + '...' if (csrf_meta or csrf_hidden) else None,
                'csrf_protected': bool(csrf_meta or csrf_hidden or csrf_cookie),
            }
        except:
            pass
        self.results['csrf_analysis'] = findings
        return findings

    def check_login_cookie_behavior(self):
        findings = {}
        try:
            s = requests.Session()
            r = s.get(self.target_url, timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'})
            before_cookies = len(s.cookies)

            for path in ['/login', '/auth', '/login/', '/auth/login']:
                url = f"{self.target_url}{path}"
                r2 = s.get(url, timeout=8, allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'})
                if r2.status_code == 200:
                    html = r2.text
                    password_field = bool(re.search(r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE))
                    if password_field:
                        csrf = re.search(r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']', html, re.IGNORECASE)
                        findings['login_endpoint'] = path
                        findings['has_password_field'] = True
                        findings['has_csrf'] = bool(csrf)
                        findings['csrf_token'] = csrf.group(1)[:20] + '...' if csrf else None
                        break
        except:
            pass
        self.results['login_cookie_behavior'] = findings
        return findings

    def run_all(self):
        self.analyze_cookies()
        self.analyze_csrf()
        self.check_login_cookie_behavior()
        return self.results
