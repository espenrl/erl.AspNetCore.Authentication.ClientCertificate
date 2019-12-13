using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public interface IClientCertificateRepository
    {
        Task<(bool CertificateFound, ClientCertificateInfo Result)> TryGetCertificate(string thumbprint, CancellationToken cancellationToken);
        IAsyncEnumerable<ClientCertificateInfo> GetAllCertificates(CancellationToken cancellationToken);
        /// <summary>
        /// For new entries only. Use UpdateCertificateEntry to update details on an existing entry.
        /// </summary>
        Task SaveCertificate(string thumbprint, string description, string role, byte[] certificateBytes, CancellationToken cancellationToken);
        Task UpdateCertificateEntry(string thumbprint, string description, string role, CancellationToken cancellationToken);
        Task RemoveCertificate(string thumbprint, CancellationToken cancellationToken);
    }
}