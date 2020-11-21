using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public class DefaultCertificateGeneratorOptions
    {
        public int RsaKeySizeInBits { get; set; } = 4096;
        public RSASignaturePadding RsaSignaturePaddingScheme { get; set; } = RSASignaturePadding.Pkcs1;
        public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA512;
        public PbeEncryptionAlgorithm PemEncryptionAlgorithm { get; set; } = PbeEncryptionAlgorithm.Aes256Cbc;
    }

    public class DefaultCertificateGenerator : ICertificateGenerator
    {
        private readonly DefaultCertificateGeneratorOptions _options;

        public DefaultCertificateGenerator(DefaultCertificateGeneratorOptions options)
        {
            _options = options;
        }

        /// <summary>
        /// Generated self signed client certificates using RSA algorithm with SHA256 hashing.
        /// NOTE: ECDSA client certificates does not work well with .NET Core 3.1 HttpClient as of November 2020.
        /// </summary>
        public X509Certificate2 GenerateCertificate(string subjectName, string friendlyName, DateTime notBefore, DateTime notAfter)
        {
            using var rsa = RSA.Create(_options.RsaKeySizeInBits);
            var req = new CertificateRequest(subjectName, rsa, _options.HashAlgorithm, _options.RsaSignaturePaddingScheme)
            {
                CertificateExtensions =
                {
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
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
            var pbeParameters = new PbeParameters(_options.PemEncryptionAlgorithm, _options.HashAlgorithm, 100_000);
            var privateKeyBytes = certificate.GetRSAPrivateKey().ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
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