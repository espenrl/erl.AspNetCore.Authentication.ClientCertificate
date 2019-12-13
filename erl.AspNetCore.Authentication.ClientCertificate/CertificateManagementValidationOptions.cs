using System.Collections.Immutable;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class CertificateManagementValidationOptions
    {
        /// <summary>
        /// Name of all roles that are allowed to be authenticated.
        /// NOTE: Provides a verification of the role names returned by IClientCertificateRepository.
        /// </summary>
        public ImmutableHashSet<string> SecurityClearanceRoles { get; set; } = ImmutableHashSet<string>.Empty
            .Add(ClientCertificateManagementDefaults.ManageClientCertificatesRoleName);
    }
}