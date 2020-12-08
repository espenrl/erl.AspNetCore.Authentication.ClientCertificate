using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using erl.AspNetCore.Authentication.ClientCertificate;
using Microsoft.Extensions.Options;

namespace Example.HealthChecksUI
{
    public class InMemoryClientCertificateOptions
    {
        public X509Certificate2 MasterCertificate { get; set; } = default!;
    }

    public class InMemoryClientCertificateRepository : IClientCertificateRepository
    {
        private ImmutableDictionary<string, ClientCertificateInfo> _inMemoryData;

        public InMemoryClientCertificateRepository(IOptions<InMemoryClientCertificateOptions> certificateManagementOptions)
        {
            var certificate = certificateManagementOptions.Value.MasterCertificate;
            _inMemoryData = ImmutableDictionary<string, ClientCertificateInfo>
                .Empty
                .WithComparers(StringComparer.OrdinalIgnoreCase)
                .Add(certificate.Thumbprint, new ClientCertificateInfo(certificate, "Default management access", ClientCertificateManagementDefaults.ManageClientCertificatesRoleName));
        }

        public Task<(bool CertificateFound, ClientCertificateInfo Result)> TryGetCertificate(string thumbprint, CancellationToken _)
        {
            var certificateFound = _inMemoryData.TryGetValue(thumbprint, out var clientCertificateInfo);
            return Task.FromResult((certificateFound, clientCertificateInfo!));
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        public async IAsyncEnumerable<ClientCertificateInfo> GetAllCertificates([EnumeratorCancellation] CancellationToken _)
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
        {
            foreach (var clientCertificate in _inMemoryData.Values)
            {
                yield return clientCertificate;
            }
        }

        public Task SaveCertificate(string thumbprint, string description, string role, byte[] certificateBytes, CancellationToken cancellationToken)
        {
            if (_inMemoryData.ContainsKey(thumbprint))
            {
                throw new Exception("Certificate already exists.");
            }

            var certificate = new X509Certificate2(certificateBytes);
            _inMemoryData = _inMemoryData.Add(thumbprint, new ClientCertificateInfo(certificate, description, role));

            return Task.CompletedTask;
        }

        public Task UpdateCertificateEntry(string thumbprint, string description, string role, CancellationToken _)
        {
            if (!_inMemoryData.TryGetValue(thumbprint, out var clientCertificateInfo))
            {
                throw new Exception("Certificate not found.");
            }

            _inMemoryData = _inMemoryData
                .Remove(thumbprint)
                .Add(thumbprint, new ClientCertificateInfo(clientCertificateInfo.Certificate, description, role));

            return Task.CompletedTask;
        }

        public Task RemoveCertificate(string thumbprint, CancellationToken _)
        {
            return Task.CompletedTask;
        }
    }
}