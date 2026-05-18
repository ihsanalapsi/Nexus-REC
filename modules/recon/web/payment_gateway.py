import requests
import json
import re
from urllib.parse import urljoin, urlparse


class PaymentGatewayRecon:
    PAYMENT_DOMAINS = {
        'stripe': ['stripe.com', 'js.stripe.com', 'api.stripe.com'],
        'tabby': ['tabby.ai', 'checkout.tabby.ai', 'api.tabby.ai'],
        'tamara': ['tamara.co', 'api.tamara.co', 'api-sandbox.tamara.co', 'checkout.tamara.co'],
        'paypal': ['paypal.com', 'api.paypal.com', 'www.paypal.com', 'sandbox.paypal.com'],
        'paddle': ['paddle.com', 'vendors.paddle.com', 'checkout.paddle.com'],
        'adyen': ['adyen.com', 'checkoutshopper-live.adyen.com', 'checkoutshopper-test.adyen.com'],
        'moyasar': ['moyasar.com', 'api.moyasar.com'],
        'myfatoorah': ['myfatoorah.com', 'api.myfatoorah.com'],
        'tap': ['tap.company', 'api.tap.company'],
        'paytabs': ['paytabs.com', 'api.paytabs.com'],
        'fort': ['fort.com', 'api.fort.com'],
        'two_checkout': ['2checkout.com', 'api.2checkout.com'],
        'razorpay': ['razorpay.com', 'api.razorpay.com'],
        'instamojo': ['instamojo.com', 'api.instamojo.com'],
        'ccavenue': ['ccavenue.com', 'secure.ccavenue.com'],
        'billplz': ['billplz.com', 'api.billplz.com'],
        'midtrans': ['midtrans.com', 'api.midtrans.com'],
        'xendit': ['xendit.co', 'api.xendit.co'],
        'dlocal': ['dlocal.com', 'api.dlocal.com'],
        'mercadopago': ['mercadopago.com', 'api.mercadopago.com'],
        'pagseguro': ['pagseguro.com', 'api.pagseguro.com'],
        'flutterwave': ['flutterwave.com', 'api.flutterwave.com'],
        'paystack': ['paystack.com', 'api.paystack.com'],
        'zarinpal': ['zarinpal.com', 'api.zarinpal.com'],
        'idpay': ['idpay.ir', 'api.idpay.ir'],
    }

    PAYMENT_SCRIPTS = {
        'stripe': r'https?://js\.stripe\.com/',
        'tabby': r'https?://checkout\.tabby\.ai/',
        'tamara': r'https?://checkout\.tamara\.co/',
        'paypal': r'https?://(?:www\.)?paypal\.com/sdk/js',
        'paddle': r'https?://cdn\.paddle\.com/paddle\.',
    }

    STRIPE_KEY_PATTERN = re.compile(r'(?:pk|sk)_(?:live|test)_[A-Za-z0-9]{16,}')
    TABBY_KEY_PATTERN = re.compile(r'pk_(?:test|live)_[A-Za-z0-9-]{20,}')
    TABBY_MERCHANT_PATTERN = re.compile(r'merchant[Cc]ode[=:]["\']?([a-zA-Z0-9_-]+)')
    GOOGLE_PAY_KEY = re.compile(r'AIza[0-9A-Za-z_-]{35}')

    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.results = {}
        self.initial_html = ''
        self.initial_csp = ''

    def set_initial_response(self, html='', csp=''):
        self.initial_html = html or ''
        self.initial_csp = csp or ''

    def from_csp(self, csp_header):
        findings = {}
        if not csp_header:
            return findings
        for gateway, domains in self.PAYMENT_DOMAINS.items():
            found_domains = [d for d in domains if d in csp_header]
            if found_domains:
                directives = []
                for direction in ['script-src', 'frame-src', 'connect-src', 'img-src']:
                    if direction in csp_header:
                        for d in found_domains:
                            if d in csp_header:
                                directives.append(direction)
                findings[gateway] = {
                    'detected_in_csp': True,
                    'domains': found_domains,
                    'directives': list(set(directives)),
                }
        return findings

    def from_html(self, html):
        findings = {}
        if not html:
            return findings
        for gateway, pattern in self.PAYMENT_SCRIPTS.items():
            if re.search(pattern, html, re.IGNORECASE):
                if gateway not in findings:
                    findings[gateway] = {'detected_in_html': True, 'scripts': []}
                findings[gateway]['detected_in_html'] = True
        return findings

    def extract_payment_keys(self, html):
        keys = {}
        stripe_keys = self.STRIPE_KEY_PATTERN.findall(html)
        if stripe_keys:
            for k in set(stripe_keys):
                mode = 'live' if 'live' in k else 'test'
                key_type = 'publishable' if k.startswith('pk') else 'secret'
                keys.setdefault('stripe', []).append({
                    'key': k[:30] + '...',
                    'mode': mode,
                    'type': key_type,
                })
        tabby_keys = self.TABBY_KEY_PATTERN.findall(html)
        if tabby_keys:
            for k in set(tabby_keys):
                mode = 'live' if 'live' in k else 'test'
                keys.setdefault('tabby', []).append({
                    'key': k[:30] + '...',
                    'mode': mode,
                    'type': 'publishable',
                })
        merchant_codes = self.TABBY_MERCHANT_PATTERN.findall(html)
        if merchant_codes:
            keys.setdefault('tabby_merchant', []).extend(set(merchant_codes))
        return keys

    def probe_payment_endpoints(self, base_url):
        endpoints = [
            '/api/order/all', '/api/order/my', '/api/orders',
            '/api/payment/all', '/api/payments', '/api/payment',
            '/api/invoice/all', '/api/invoices', '/api/invoice',
            '/api/transaction/all', '/api/transactions',
            '/api/billing', '/api/billing/history',
            '/api/user/all', '/api/users',
            '/api/cart', '/api/cart/all',
            '/api/checkout', '/api/subscription',
        ]
        found = []
        for path in endpoints:
            url = f"{base_url}{path}"
            try:
                r = requests.get(url, timeout=8,
                    headers={'User-Agent': 'Mozilla/5.0'},
                    allow_redirects=False)
                if r.status_code in [200, 201] and len(r.content) > 20:
                    ct = r.headers.get('Content-Type', '')
                    found.append({
                        'endpoint': path,
                        'status': r.status_code,
                        'size': len(r.content),
                        'content_type': ct[:50],
                    })
            except:
                pass
        return found

    @staticmethod
    def classify_payment_data(response_json):
        analysis = {
            'payment_methods_detected': [],
            'payment_fields': [],
            'pii_fields': [],
            'has_livemode': None,
            'is_test_mode': None,
            'has_client_secret': False,
            'has_card_info': False,
            'has_tabby': False,
            'has_tamara': False,
            'total_records': 0,
            'sample_record': None,
        }
        if not response_json:
            return analysis
        if isinstance(response_json, dict):
            if 'data' in response_json:
                records = response_json['data']
            elif 'orders' in response_json:
                records = response_json['orders']
            elif 'users' in response_json:
                records = response_json['users']
            elif 'payments' in response_json:
                records = response_json['payments']
            else:
                records = [response_json]
        elif isinstance(response_json, list):
            records = response_json
        else:
            return analysis
        if not isinstance(records, list):
            return analysis
        analysis['total_records'] = len(records)
        for record in records[:10]:
            if not isinstance(record, dict):
                continue
            if analysis['sample_record'] is None:
                analysis['sample_record'] = record
            payment_method = record.get('paymentMethod', record.get('payment_method', ''))
            if payment_method:
                if payment_method not in analysis['payment_methods_detected']:
                    analysis['payment_methods_detected'].append(payment_method)
            pi = record.get('paymentIntent', {})
            if pi and isinstance(pi, dict):
                analysis['payment_fields'].append('paymentIntent')
                if pi.get('client_secret'):
                    analysis['has_client_secret'] = True
                lv = pi.get('livemode')
                if lv is not None:
                    analysis['has_livemode'] = lv
                    analysis['is_test_mode'] = not lv
            ci = record.get('cardInfo', record.get('card_info', {}))
            if ci and isinstance(ci, dict) and ci.get('card'):
                analysis['payment_fields'].append('cardInfo')
                analysis['has_card_info'] = True
            tb = record.get('tabby', {})
            if tb and isinstance(tb, dict):
                analysis['payment_fields'].append('tabby')
                analysis['has_tabby'] = True
                raw = tb.get('raw', {})
                if raw and isinstance(raw, dict):
                    payment = raw.get('payment', {})
                    if payment:
                        is_test = payment.get('is_test')
                        if is_test is not None:
                            analysis['is_test_mode'] = is_test
            tm = record.get('tamara', {})
            if tm and isinstance(tm, dict):
                analysis['payment_fields'].append('tamara')
                analysis['has_tamara'] = True
                if tm.get('orderId') or tm.get('checkoutId'):
                    analysis['has_tamara'] = True
            for pii_field in ['name', 'email', 'contact', 'address', 'phone']:
                if record.get(pii_field):
                    if pii_field not in analysis['pii_fields']:
                        analysis['pii_fields'].append(pii_field)
            user = record.get('user', {})
            if isinstance(user, dict):
                for pii_field in ['name', 'email', 'phone']:
                    if user.get(pii_field):
                        if f'user.{pii_field}' not in analysis['pii_fields']:
                            analysis['pii_fields'].append(f'user.{pii_field}')
        return analysis

    @staticmethod
    def detect_payment_webhooks(js_content):
        webhooks = []
        patterns = [
            r'stripe\.com/webhook',
            r'stripe\.com/v1/webhook_endpoints',
            r'webhook.*stripe',
            r'tabby.*webhook',
            r'tamara.*webhook',
            r'/api/webhook',
            r'/webhook/',
            r'webhookSecret',
            r'whsec_',
            r'webhook.*signing.secret',
        ]
        for pat in patterns:
            matches = re.findall(pat, js_content, re.IGNORECASE)
            webhooks.extend(matches[:5])
        return list(set(webhooks)) if webhooks else []

    def run_all(self, html='', csp='', base_url='', js_files=None):
        self.results = {}
        if not base_url:
            base_url = self.target_url
        if not html:
            html = self.initial_html
        if not csp:
            csp = self.initial_csp
        if not html and not csp:
            try:
                response = requests.get(
                    self.target_url,
                    timeout=10,
                    headers={'User-Agent': 'Mozilla/5.0'},
                )
                html = response.text
                csp = response.headers.get('Content-Security-Policy', response.headers.get('content-security-policy', ''))
            except Exception:
                pass
        if csp:
            self.results['csp_analysis'] = self.from_csp(csp)
        if html:
            self.results['html_analysis'] = self.from_html(html)
            self.results['payment_keys'] = self.extract_payment_keys(html)
        if base_url:
            self.results['payment_endpoints'] = self.probe_payment_endpoints(base_url)
        if js_files:
            self.results['webhooks'] = []
            for js_content in js_files:
                wh = self.detect_payment_webhooks(js_content)
                self.results['webhooks'].extend(wh)
            self.results['webhooks'] = list(set(self.results['webhooks']))
        return self.results
