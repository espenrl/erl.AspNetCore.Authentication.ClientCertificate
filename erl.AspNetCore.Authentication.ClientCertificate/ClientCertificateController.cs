using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    [ApiController]
    [Route("api/{controller}/{action}")]
    [Authorize(ClientCertificateManagementDefaults.ManageClientCertificatesPolicyName)]
    public class ClientCertificateController : Controller
    {
        private readonly ICertificateGenerator _certificateGenerator;
        private readonly IClientCertificateRepository _clientCertificateRepository;
        private readonly ImmutableHashSet<string> _assignableRoles;

        public ClientCertificateController(
            IOptions<CertificateManagementUiOptions> uiOptions,
            IOptions<CertificateManagementValidationOptions> validationOptions,
            ICertificateGenerator certificateGenerator,
            IClientCertificateRepository clientCertificateRepository)
        {
            if (uiOptions == null) throw new ArgumentNullException(nameof(uiOptions));
            if (validationOptions == null) throw new ArgumentNullException(nameof(validationOptions));

            _certificateGenerator = certificateGenerator ?? throw new ArgumentNullException(nameof(certificateGenerator));
            _clientCertificateRepository = clientCertificateRepository ?? throw new ArgumentNullException(nameof(clientCertificateRepository));

            if (!uiOptions.Value.AssignableRoles.IsEmpty
                && !uiOptions.Value.AssignableRoles.IsSubsetOf(validationOptions.Value.SecurityClearanceRoles))
            {
                var msg = $"{nameof(CertificateManagementUiOptions)}.{nameof(CertificateManagementUiOptions.AssignableRoles)} should be a subset of {nameof(CertificateManagementValidationOptions)}.{nameof(CertificateManagementValidationOptions.SecurityClearanceRoles)}";
                throw new Exception(msg);
            }

            _assignableRoles = !uiOptions.Value.AssignableRoles.IsEmpty
            ? uiOptions.Value.AssignableRoles
            : validationOptions.Value.SecurityClearanceRoles;
        }

        [HttpGet]
        public async Task<ActionResult<List<ClientCertificateViewModel>>> GetAll()
        {
            var clientCertificates = _clientCertificateRepository
                .GetAllCertificates(HttpContext.RequestAborted)
                .WithCancellation(HttpContext.RequestAborted)
                .ConfigureAwait(false);

            var result = new List<ClientCertificateViewModel>();
            await foreach (var clientCertificate in clientCertificates)
            {
                result.Add(new ClientCertificateViewModel(
                    clientCertificate.Certificate.Thumbprint,
                    clientCertificate.Certificate.Subject,
                    clientCertificate.Certificate.NotAfter,
                    clientCertificate.Description,
                    clientCertificate.Role
                    ));
            }
            return Ok(result);
        }

        [HttpGet]
        public ActionResult<ImmutableHashSet<string>> GetAllRoles()
        {
            return _assignableRoles;
        }

        [HttpPost]
        public async Task<ActionResult> RemoveCertificate([FromBody] RemoveCertificateModel model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            if (string.IsNullOrWhiteSpace(model.Thumbprint))
            {
                ModelState.AddModelError("Certificate", "Thumbprint must be given");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var thumbprintLowercased = model.Thumbprint.ToLowerInvariant();

            var (certificateFound, _) = await _clientCertificateRepository
                .TryGetCertificate(thumbprintLowercased, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            if (!certificateFound)
            {
                return NotFound();
            }

            await _clientCertificateRepository
                .RemoveCertificate(thumbprintLowercased, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            return Ok();
        }

        [HttpPost]
        public async Task<ActionResult> Update([FromBody] UpdateCertificateModel model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            if (!_assignableRoles.Contains(model.Role))
            {
                ModelState.AddModelError("Role", "Invalid security clearance given");
            }

            if (string.IsNullOrWhiteSpace(model.Description))
            {
                ModelState.AddModelError("Description", "Description must be given");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var thumbprintLowercased = model.Thumbprint.ToLowerInvariant();

            var (certificateFound, _) = await _clientCertificateRepository
                .TryGetCertificate(thumbprintLowercased, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            if (!certificateFound)
            {
                return NotFound();
            }

            await _clientCertificateRepository
                .UpdateCertificateEntry(thumbprintLowercased, model.Description, model.Role, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            return Ok();
        }

        [HttpPost]
        public async Task<ActionResult> Upload([FromBody] UploadCertificateModel model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            if (string.IsNullOrWhiteSpace(model.CertificateEncoded))
            {
                ModelState.AddModelError("Certificate", "Certificate must be given");
            }

            if (string.IsNullOrWhiteSpace(model.Description))
            {
                ModelState.AddModelError("Description", "Description must be given");
            }

            if (!_assignableRoles.Contains(model.Role))
            {
                ModelState.AddModelError("Role", "Invalid security clearance given");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            string thumbprint;
            byte[] certificateBytes;

            try
            {
                var password = new NetworkCredential(string.Empty, model.Password).SecurePassword;
                var bytes = Convert.FromBase64String(model.CertificateEncoded);
                using var certificate = new X509Certificate2(bytes, password);

                var thumbprintLowercased = certificate.Thumbprint.ToLowerInvariant();

                var (certificateFound, _) = await _clientCertificateRepository
                    .TryGetCertificate(thumbprintLowercased, HttpContext.RequestAborted)
                    .ConfigureAwait(false);

                if (certificateFound)
                {
                    ModelState.AddModelError("Certificate", "Certificate already exists");
                    return BadRequest(ModelState);
                }

                thumbprint = thumbprintLowercased;
                certificateBytes = certificate.RawData;
            }
            catch (CryptographicException e) when (e.HResult == -2147024810)
            {
                ModelState.AddModelError("Password", "Wrong certificate passphrase.");
                return BadRequest(ModelState);
            }
            catch (CryptographicException)
            {
                ModelState.AddModelError("Certificate", "Could not read certificate.");
                return BadRequest(ModelState);
            }

            await _clientCertificateRepository
                .SaveCertificate(thumbprint, model.Description, model.Role, certificateBytes, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            return Ok();
        }

        [HttpPost]
        public async Task<ActionResult> Generate([FromBody] GenerateCertificateModel model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            if (string.IsNullOrWhiteSpace(model.Password))
            {
                ModelState.AddModelError("Password", "Passphrase must be given");
            }

            if (string.IsNullOrWhiteSpace(model.Description))
            {
                ModelState.AddModelError("Description", "Description must be given");
            }

            if (!_assignableRoles.Contains(model.Role))
            {
                ModelState.AddModelError("Role", "Invalid security clearance given");
            }

            var notAfter = DateTime.Today.AddMonths(model.ValidForMonths);
            if (notAfter < DateTime.Today)
            {
                ModelState.AddModelError("NotAfter", "Invalid number of months, needs to be in the future");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var subjectName = EncodeCsrField($"CN={model.Description}");
            var friendlyName = EncodeCsrField(model.Description);
            var certificate = await Task
                .Run(() => _certificateGenerator.GenerateCertificate(subjectName, friendlyName, DateTime.Today, notAfter))
                .ConfigureAwait(false);

            var thumbprintLowercased = certificate.Thumbprint.ToLowerInvariant();

            await _clientCertificateRepository
                .SaveCertificate(thumbprintLowercased, model.Description, model.Role, certificate.RawData, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            var fileName = EncodeFileName(model.Description);
            var zipStream = CreateClientCertificateZipStream(certificate, fileName, model.Password, _certificateGenerator);
            return File(zipStream, "application/octet-stream", $"{fileName}.zip");
        }

        private static Stream CreateClientCertificateZipStream(X509Certificate2 certificate, string fileName, string password, ICertificateGenerator certificateGenerator)
        {
            var crtBytes = certificate.Export(X509ContentType.Cert);
            var keyBytes = certificateGenerator.ExportCertificateToPemWithEncryptedPrivateKey(certificate, password);
            var pfxBytes = certificate.Export(X509ContentType.Pfx, password);

            var zipStream = new MemoryStream();
            using var zipArchive = new ZipArchive(zipStream, ZipArchiveMode.Create, true);

            // crt
            var crtEntry = zipArchive.CreateEntry($"{fileName}.crt");
            using (var crtEntryStream = crtEntry.Open())
            {
                crtEntryStream.Write(crtBytes);
            }

            // key
            var keyEntry = zipArchive.CreateEntry($"{fileName}.key");
            using (var keyEntryStream = keyEntry.Open())
            {
                keyEntryStream.Write(keyBytes);
            }

            // pfx
            var pfxEntry = zipArchive.CreateEntry($"{fileName}.pfx");
            using (var pfxEntryStream = pfxEntry.Open())
            {
                pfxEntryStream.Write(pfxBytes);
            }

            zipArchive.Dispose();
            zipStream.Seek(0, SeekOrigin.Begin);
            return zipStream;
        }

        /// <summary>
        /// Adhere to rules for X500DistinguishedName.
        /// </summary>
        private static string EncodeCsrField(string str)
        {
            var invalidCsrFieldCharacters = new[]
            { '!', '@', '#', '$', '%', '^', '*', '(', ')', '~', '?', '>', '<', '&', '/', '\\', ',', '.', '"', '\'' };
            var parts = str.Split(invalidCsrFieldCharacters, StringSplitOptions.RemoveEmptyEntries);
            return string.Join("", parts);
        }

        private static string EncodeFileName(string str)
        {
            var parts = str.Split(Path.GetInvalidFileNameChars(), StringSplitOptions.RemoveEmptyEntries);
            return string.Join("", parts);
        }
    }

    public class ClientCertificateViewModel
    {
        public ClientCertificateViewModel(string thumbprint, string subject, DateTime notAfter, string description, string role)
        {
            if (string.IsNullOrWhiteSpace(thumbprint))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(thumbprint));
            if (string.IsNullOrWhiteSpace(subject))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(subject));
            if (string.IsNullOrWhiteSpace(description))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(description));
            if (string.IsNullOrWhiteSpace(role))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(role));

            Thumbprint = thumbprint;
            Subject = subject;
            NotAfter = notAfter;
            Description = description;
            Role = role;
        }

        public string Thumbprint { get; }
        public string Subject { get; }
        public DateTime NotAfter { get; }
        public string Description { get; }
        public string Role { get; }
    }

    public class GenerateCertificateModel
    {
        public string Description { get; set; }
        public string Role { get; set; }
        public string Password { get; set; }
        public int ValidForMonths { get; set; }
    }

    public class UploadCertificateModel
    {
        public string Description { get; set; }
        public string Role { get; set; }
        public string Password { get; set; }
        public string CertificateEncoded { get; set; }
    }

    public class UpdateCertificateModel
    {
        public string Thumbprint { get; set; }
        public string Description { get; set; }
        public string Role { get; set; }
    }

    public class RemoveCertificateModel
    {
        public string Thumbprint { get; set; }
    }
}
