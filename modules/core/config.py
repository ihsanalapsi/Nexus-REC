VERSION = "1.0.1"
SCAN_MODES = ("safe", "active", "aggressive")

MODULES_REGISTRY = {
    'basic': 'modules.recon.fingerprint.basic.BasicRecon',
    'subdomain': 'modules.recon.infra.subdomain.SubdomainRecon',
    'js': 'modules.recon.web.js.JSRecon',
    'graphql': 'modules.recon.web.graphql.GraphQLRecon',
    'cloud': 'modules.recon.infra.cloud.CloudRecon',
    'secrets': 'modules.recon.web.secrets.SecretsRecon',
    'vuln': 'modules.exploit.scanner.VulnScanner',
    'business': 'modules.exploit.business_logic.BusinessLogicScanner',
    'cookies': 'modules.recon.web.cookies.CookieRecon',
    'dns': 'modules.recon.infra.dns.DNSRecon',
    'endpoints': 'modules.recon.web.endpoints.EndpointRecon',
    'payment': 'modules.recon.web.payment_gateway.PaymentGatewayRecon',
    'backend_scan': 'modules.recon.web.backend_scan.BackendScanRecon',
    'supabase_rls': 'modules.recon.platforms.supabase_rls.SupabaseRLSRecon',
    'supabase_rpc': 'modules.recon.platforms.supabase_rpc.SupabaseRPCRecon',
    'supabase_storage': 'modules.recon.platforms.supabase_storage.SupabaseStorageRecon',
    'wellknown': 'modules.recon.web.wellknown.WellKnownRecon',
    'apk': 'modules.recon.mobile.apk_analysis.APKRecon',
    'dns_detritus': 'modules.recon.infra.dns_detritus.DNSDetritusRecon',
    'admin_scan': 'modules.recon.infra.admin_scan.AdminScanRecon',
}

STACK_MODULES = {
    'Next.js': 'modules.stack.nextjs.NextJSRecon',
    'Laravel': 'modules.stack.laravel.LaravelRecon',
}
