VERSION = "1.0.0"
SCAN_MODES = ("safe", "active", "aggressive")

MODULES_REGISTRY = {
    'basic': 'modules.recon.basic.BasicRecon',
    'subdomain': 'modules.recon.subdomain.SubdomainRecon',
    'js': 'modules.recon.js.JSRecon',
    'graphql': 'modules.recon.graphql.GraphQLRecon',
    'cloud': 'modules.recon.cloud.CloudRecon',
    'secrets': 'modules.recon.secrets.SecretsRecon',
    'vuln': 'modules.exploit.scanner.VulnScanner',
    'business': 'modules.exploit.business_logic.BusinessLogicScanner',
    'cookies': 'modules.recon.cookies.CookieRecon',
    'dns': 'modules.recon.dns.DNSRecon',
    'endpoints': 'modules.recon.endpoints.EndpointRecon',
    'payment': 'modules.recon.payment_gateway.PaymentGatewayRecon',
    'supabase_rls': 'modules.recon.supabase_rls.SupabaseRLSRecon',
    'supabase_rpc': 'modules.recon.supabase_rpc.SupabaseRPCRecon',
    'supabase_storage': 'modules.recon.supabase_storage.SupabaseStorageRecon',
    'wellknown': 'modules.recon.wellknown.WellKnownRecon',
    'apk': 'modules.recon.apk_analysis.APKRecon',
    'dns_detritus': 'modules.recon.dns_detritus.DNSDetritusRecon',
    'admin_scan': 'modules.recon.admin_scan.AdminScanRecon',
}

STACK_MODULES = {
    'Next.js': 'modules.stack.nextjs.NextJSRecon',
    'Laravel': 'modules.stack.laravel.LaravelRecon',
}
