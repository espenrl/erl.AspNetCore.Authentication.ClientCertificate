using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class DefaultClientCertificateValidationService : IClientCertificateValidationService
    {
        private readonly CertificateManagementValidationOptions _options;
        private readonly IClientCertificateRepository _clientCertificateRepository;

        public DefaultClientCertificateValidationService(
            IOptions<CertificateManagementValidationOptions> options, 
            IClientCertificateRepository clientCertificateRepository,
            IMemoryCache memoryCache)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (clientCertificateRepository == null) throw new ArgumentNullException(nameof(clientCertificateRepository));

            _options = options.Value;
            _clientCertificateRepository = new CachedClientCertificateRepository(clientCertificateRepository, memoryCache);
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

        // Caches result to reduce storage load as well as improve upon DDoS attacks.
        private class CachedClientCertificateRepository : IClientCertificateRepository
        {
            private readonly IClientCertificateRepository _clientCertificateRepository;
            private readonly IMemoryCache _memoryCache;

            public CachedClientCertificateRepository(
                IClientCertificateRepository clientCertificateRepository, 
                IMemoryCache memoryCache)
            {
                _clientCertificateRepository = clientCertificateRepository;
                _memoryCache = memoryCache;
            }

            public async Task<(bool CertificateFound, ClientCertificateInfo Result)> TryGetCertificate(string thumbprint, CancellationToken cancellationToken)
            {
                var key = $"{nameof(DefaultClientCertificateValidationService)}.{thumbprint}";

                if (_memoryCache.TryGetValue(key, out (bool, ClientCertificateInfo) itemFromCache))
                {
                    return itemFromCache;
                }

                var itemFromRepository = await _clientCertificateRepository
                    .TryGetCertificate(thumbprint, cancellationToken)
                    .ConfigureAwait(false);

                var isRegisteredClientCertificate = itemFromRepository.CertificateFound;
                var slidingExpiration = isRegisteredClientCertificate
                    ? TimeSpan.FromMinutes(10) // cache registered client certificate: do not overload storage
                    : TimeSpan.FromMinutes(1); // client certificate not registered: protect against DDoS attack

                _memoryCache.Set(key, itemFromRepository, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1), // refresh from storage once an hour for up to date data (role/description)
                    SlidingExpiration = slidingExpiration
                });

                return itemFromRepository;
            }

            public IAsyncEnumerable<ClientCertificateInfo> GetAllCertificates(CancellationToken cancellationToken) 
                => throw new NotImplementedException($"Not used by {nameof(DefaultClientCertificateValidationService)}.");

            public Task SaveCertificate(string thumbprint, string description, string role, byte[] certificateBytes, CancellationToken cancellationToken) 
                => throw new NotImplementedException($"Not used by {nameof(DefaultClientCertificateValidationService)}.");

            public Task UpdateCertificateEntry(string thumbprint, string description, string role, CancellationToken cancellationToken) 
                => throw new NotImplementedException($"Not used by {nameof(DefaultClientCertificateValidationService)}.");

            public Task RemoveCertificate(string thumbprint, CancellationToken cancellationToken) 
                => throw new NotImplementedException($"Not used by {nameof(DefaultClientCertificateValidationService)}.");
        }
    }
}