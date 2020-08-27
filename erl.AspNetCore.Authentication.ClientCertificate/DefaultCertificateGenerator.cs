using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class DefaultCertificateGenerator : ICertificateGenerator
    {
        /// <summary>
        /// Generated self signed client certificates using elliptic curve algorithm with SHA256 hashing.
        /// </summary>
        public X509Certificate2 GenerateCertificate(string subjectName, string friendlyName, DateTime notBefore, DateTime notAfter)
        {
            using var ecDsa = ECDsa.Create();
            var req = new CertificateRequest(subjectName, ecDsa, HashAlgorithmName.SHA256)
            {
                CertificateExtensions =
                {
                    new X509BasicConstraintsExtension(false, false, 0, true),
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
							new Oid("1.3.6.1.5.5.7.3.1"), // TLS server authentication
                            new Oid("1.3.6.1.5.5.7.3.2")  // TLS client authentication
                        }, true)
                }
            };
            var certificate = req.CreateSelfSigned(notBefore, notAfter);
            certificate.FriendlyName = friendlyName;
            return certificate;
        }

        public byte[] ExportCertificateToPemWithEncryptedPrivateKey(X509Certificate2 certificate, string password)
        {
            var pbeParameters = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            var privateKeyBytes = certificate.GetECDsaPrivateKey().ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN EC PRIVATE KEY-----");
            builder.AppendLine("Proc-Type: 4,ENCRYPTED");
            builder.AppendLine();

            var base64PrivateKeyString = Convert.ToBase64String(privateKeyBytes);
            var offset = 0;
            const int lineLength = 64;
            while (offset < base64PrivateKeyString.Length)
            {
                var lineEnd = Math.Min(offset + lineLength, base64PrivateKeyString.Length);
                builder.Append(base64PrivateKeyString.AsSpan(offset, lineEnd - offset));
                builder.AppendLine();
                offset = lineEnd;
            }

            builder.AppendLine("-----END EC PRIVATE KEY-----");
            return Encoding.ASCII.GetBytes(builder.ToString());
        }
    }
}