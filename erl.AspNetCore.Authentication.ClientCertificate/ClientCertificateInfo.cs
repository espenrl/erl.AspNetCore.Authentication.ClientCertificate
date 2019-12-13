using System;
using System.Security.Cryptography.X509Certificates;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class ClientCertificateInfo
    {
        public ClientCertificateInfo(X509Certificate2 certificate, string description, string role)
        {
            if (string.IsNullOrWhiteSpace(description))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(description));
            if (string.IsNullOrWhiteSpace(role))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(role));

            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            Description = description;
            Role = role;
        }

        /// <summary>
        /// Certificate without private key.
        /// </summary>
        public X509Certificate2 Certificate { get; }
        /// <summary>
        /// Free text description associated with the certificate.
        /// </summary>
        public string Description { get; }
        /// <summary>
        /// Value to be assigned to identity role claim upon authentication.
        /// </summary>
        public string Role { get; }
    }
}