using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using erl.AspNetCore.Authentication.ClientCertificate;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Example.Basic
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            static void ConfigureCertificateValidation(CertificateAuthenticationOptions options)
            {
                options.AllowedCertificateTypes = CertificateTypes.All; // allow self signed certificates
            }

            // setup custom IClientCertificateRepository
            services
                .AddSingleton<IClientCertificateRepository, InMemoryClientCertificateRepository>()
                .AddOptions<InMemoryClientCertificateOptions>()
                .Configure<IConfiguration>((options, configuration) => 
                    options.MasterCertificate = new X509Certificate2(File.ReadAllBytes("Client Certificate Management UI example.pfx"), "notasecret"));

            // enable API for client certificate management UI
            services.AddClientCertificateManagementUiApi();

            // setup authentication / authorization pipeline
            services
                .AddAuthorization()
                .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                .AddCertificate(ConfigureCertificateValidation) // basic certificate validation (Microsoft)
                .AddCertificateAuthentication(); // validate certificate against IClientCertificateRepository and assign role claim upon successful authentication
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app
                .UseRouting()
                .UseAuthentication()
                .UseAuthorization()
                .UseEndpoints(endpoints =>
                {
                    endpoints.MapClientCertificateManagementUi();
                    endpoints.MapGet("/", RenderIndexPage);
                });
        }

        private static async Task RenderIndexPage(HttpContext context)
        {
            if (!context.User.Identity?.IsAuthenticated ?? false)
            {
                await context.Response.WriteAsync("<h1>Your client certificate is not known by this site.</h1>");
                return;
            }

            var roleClaims = context.User.Claims.Where(c => c.Type == ClaimTypes.Role);
            var roleStr = string.Join(",", roleClaims.Select(r => r.Value));

            context.Response.Headers.Add("Content-Type", "text/html");
            await context.Response.WriteAsync("<h1>Hi! You have authenticated using a client certificate.</h1>");
            await context.Response.WriteAsync($"<p>Your role claim is: <b>{roleStr}</b></p>");

            if (context.User.IsInRole(ClientCertificateManagementDefaults.ManageClientCertificatesRoleName))
            {
                await context.Response.WriteAsync("<h2><a href=\"/managecertificates\">Manage client certificates</a></h2>");
            }
        }
    }
}
