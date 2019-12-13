using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class DefaultClientCertificateValidationService : IClientCertificateValidationService
    {
        private readonly CertificateManagementValidationOptions _options;
        private readonly IClientCertificateRepository _clientCertificateRepository;

        public DefaultClientCertificateValidationService(
            IOptions<CertificateManagementValidationOptions> options, 
            IClientCertificateRepository clientCertificateRepository)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            _options = options.Value;
            _clientCertificateRepository = clientCertificateRepository ?? throw new ArgumentNullException(nameof(clientCertificateRepository));
        }

        public async Task ValidateCertificate(X509Certificate2 certificate, ClientCertificateValidationContext context)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (context == null) throw new ArgumentNullException(nameof(context));

            var thumbprintLowercased = certificate.Thumbprint.ToLowerInvariant();

            var (certificateFound, clientCertificate) = await _clientCertificateRepository.
                TryGetCertificate(thumbprintLowercased, CancellationToken.None)
                .ConfigureAwait(false);

            if (!certificateFound)
            {
                context.Fail("Client certificate not found in store by thumbprint.");
                return;
            }

            if (!ByteArrayEquals(certificate.RawData, clientCertificate.Certificate.RawData))
            {
                context.Fail("Client certificate is not equal do the one in the store (byte comparison).");
                return;
            }

            if (!_options.SecurityClearanceRoles.Contains(clientCertificate.Role))
            {
                context.Fail($"Client certificate registration has a role value which is not listed in {nameof(CertificateManagementValidationOptions)}.{nameof(CertificateManagementValidationOptions.SecurityClearanceRoles)}.");
                return;
            }

            context.Success(clientCertificate);
        }

        private static bool ByteArrayEquals(byte[] arr1, byte[] arr2)
        {
            if (arr1 == null) throw new ArgumentNullException(nameof(arr1));
            if (arr2 == null) throw new ArgumentNullException(nameof(arr2));

            if (arr1.Length != arr2.Length)
            {
                return false;
            }

            for (var i = 0; i < arr1.Length; i++)
            {
                if (arr1[i] != arr2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}