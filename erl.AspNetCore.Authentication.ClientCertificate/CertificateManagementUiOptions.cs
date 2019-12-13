using System;
using System.Collections.Immutable;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class CertificateManagementUiOptions
    {
        /// <summary>
        /// Name of all roles that can be assigned to a certificate. Default value is an empty list.
        /// NOTE: If empty then CertificateManagementValidationOptions.SecurityClearanceRoles will be used instead.
        /// </summary>
        public ImmutableHashSet<string> AssignableRoles { get; set; } = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase);
    }
}