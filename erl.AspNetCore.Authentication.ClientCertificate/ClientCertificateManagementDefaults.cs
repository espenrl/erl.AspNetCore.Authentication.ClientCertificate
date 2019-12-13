namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public static class ClientCertificateManagementDefaults
    {
        // portal
        public const string ManagementPortalDisplayName = "Client certificate management";
        public const string ManagementPortalUri = "/managecertificates";
        public const string ManagementPortalRoute = "/managecertificates/{*path}";

        // authorization
        public const string ManageClientCertificatesPolicyName = "ManageClientCertificates";
        public const string ManageClientCertificatesRoleName = "ClientCertificateManager";
    }
}