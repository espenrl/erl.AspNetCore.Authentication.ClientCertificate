using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.FileProviders;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public static class EndpointRouteBuilderExtensions
    {
        public static IEndpointConventionBuilder MapClientCertificateManagementUi(this IEndpointRouteBuilder endpointRouteBuilder)
        {
            if (endpointRouteBuilder == null) throw new ArgumentNullException(nameof(endpointRouteBuilder));

            endpointRouteBuilder.MapControllers(); // adds ClientCertificateController

            return endpointRouteBuilder
                .Map(ClientCertificateManagementDefaults.ManagementPortalRoute, endpointRouteBuilder.BuildCertificateManagementPipeline())
                .RequireAuthorization(ClientCertificateManagementDefaults.ManageClientCertificatesPolicyName)
                .WithDisplayName(ClientCertificateManagementDefaults.ManagementPortalDisplayName);
        }

        private static RequestDelegate BuildCertificateManagementPipeline(this IEndpointRouteBuilder endpointRouteBuilder)
        {
            var staticFileOptions = new StaticFileOptions
            {
                FileProvider = new EmbeddedFileProvider(typeof(ClientCertificateManagementDefaults).Assembly, typeof(ClientCertificateManagementDefaults).Namespace),
                HttpsCompression = HttpsCompressionMode.Compress,
                RequestPath = ClientCertificateManagementDefaults.ManagementPortalUri
            };

            var fallbackStaticFileOptions = new StaticFileOptions
            {
                FileProvider = new EmbeddedFileProvider(typeof(ClientCertificateManagementDefaults).Assembly, typeof(ClientCertificateManagementDefaults).Namespace),
                HttpsCompression = HttpsCompressionMode.Compress
            };

            return endpointRouteBuilder
                .CreateApplicationBuilder()
                .Use(async (context, continuation) =>
                {
                    // unset endpoint or else StaticFileMiddleware will refuse to process
                    context.SetEndpoint(null);
                    await continuation().ConfigureAwait(false);
                })
                .UseStaticFiles(staticFileOptions)
                .UseRouting()
                .UseEndpoints(e => e.MapFallbackToFile("{*path}", "index.html", fallbackStaticFileOptions))
                .Build();
        }
    }
}