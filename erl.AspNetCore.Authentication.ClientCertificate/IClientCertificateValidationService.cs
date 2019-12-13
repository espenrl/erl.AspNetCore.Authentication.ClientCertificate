using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class ClientCertificateValidationContext
    {
        public bool IsFail { get; private set; }
        public bool IsSuccess { get; private set; }
        public string FailureMessage { get; private set; }
        public ClientCertificateInfo ClientCertificate { get; private set; }

        public void Fail(string failureMessage)
        {
            if (string.IsNullOrWhiteSpace(failureMessage))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(failureMessage));

            IsFail = true;
            FailureMessage = failureMessage;
        }

        public void Success(ClientCertificateInfo clientCertificate)
        {
            IsSuccess = true;
            ClientCertificate = clientCertificate ?? throw new ArgumentNullException(nameof(clientCertificate));
        }
    }

    public interface IClientCertificateValidationService
    {
        Task ValidateCertificate(X509Certificate2 certificate, ClientCertificateValidationContext context);
    }
}