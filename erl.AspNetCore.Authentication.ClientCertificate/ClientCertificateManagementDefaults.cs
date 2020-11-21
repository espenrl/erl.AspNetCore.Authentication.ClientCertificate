namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public static class ClientCertificateManagementDefaults
    {
        // portal
        public const string ManagementPortalDisplayName = "Client certificate management";
        public const string ManagementPortalAssetsUri = "/managecertificates/assets";
        public const string ManagementPortalAssetsRoute = "/managecertificates/assets/{*path}";
        public const string ManagementPortalRoute = "/managecertificates/{*path}";

        // authorization
        public const string ManageClientCertificatesPolicyName = "ManageClientCertificates";
        public const string ManageClientCertificatesRoleName = "ClientCertificateManager";
    }
}