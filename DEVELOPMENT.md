# Development

## Generate client certificate for examples

``` CSharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var ecDsa = ECDsa.Create();
var certificateRequest = new CertificateRequest("CN=ClientCertificate Management UI", ecDsa, HashAlgorithmName.SHA256)
{
    CertificateExtensions =
    {
        new X509BasicConstraintsExtension(false, false, 0, true),
        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
        new X509EnhancedKeyUsageExtension(
            new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.2"), // TLS client authentication
                new Oid("1.3.6.1.5.5.7.3.1")  // TLS server authentication
            }, false)
    }
};
var certificate = certificateRequest.CreateSelfSigned(DateTime.Today, DateTime.Today.AddYears(10));
certificate.FriendlyName = "ClientCertificate Management UI";
var pfxBytes = certificate.Export(X509ContentType.Pfx, "notasecret");
File.WriteAllBytes(@"ClientCertificate Management UI.pfx", pfxBytes);
```
