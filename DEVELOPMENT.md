# Development

## Generate client certificate for examples

``` CSharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using var rsa = RSA.Create(4096);
var certificateRequest = new CertificateRequest("CN=Client Certificate Management UI example", rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
{
    CertificateExtensions =
    {
        new X509EnhancedKeyUsageExtension(
            new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.2"), // TLS client authentication
            }, false)
    }
};
var certificate = certificateRequest.CreateSelfSigned(DateTime.Today, DateTime.Today.AddYears(10));
certificate.FriendlyName = "Client Certificate Management UI example";
var pfxBytes = certificate.Export(X509ContentType.Pfx, "notasecret");
File.WriteAllBytes(@"Client Certificate Management UI example.pfx", pfxBytes);
```
