using System;
using System.Security.Cryptography.X509Certificates;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public interface ICertificateGenerator
    {
        X509Certificate2 GenerateCertificate(string subjectName, string friendlyName, DateTime notBefore, DateTime notAfter);
        byte[] ExportCertificateToPemWithEncryptedPrivateKey(X509Certificate2 certificate, string password);
    }
}