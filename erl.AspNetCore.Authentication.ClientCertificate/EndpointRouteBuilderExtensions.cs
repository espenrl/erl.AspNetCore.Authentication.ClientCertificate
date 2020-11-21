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

            endpointRouteBuilder
                .Map(ClientCertificateManagementDefaults.ManagementPortalAssetsRoute, endpointRouteBuilder.BuildCertificateManagementAssetsPipeline())
                .RequireAuthorization(ClientCertificateManagementDefaults.ManageClientCertificatesPolicyName)
                .WithDisplayName(ClientCertificateManagementDefaults.ManagementPortalDisplayName);

            var staticFileOptions = new StaticFileOptions
            {
                FileProvider = new EmbeddedFileProvider(typeof(ClientCertificateManagementDefaults).Assembly, typeof(ClientCertificateManagementDefaults).Namespace),
                HttpsCompression = HttpsCompressionMode.Compress
            };

            return endpointRouteBuilder
                .MapFallbackToFile(ClientCertificateManagementDefaults.ManagementPortalRoute, "index.html", staticFileOptions)
                .RequireAuthorization(ClientCertificateManagementDefaults.ManageClientCertificatesPolicyName)
                .WithDisplayName(ClientCertificateManagementDefaults.ManagementPortalDisplayName);
        }

        private static RequestDelegate BuildCertificateManagementAssetsPipeline(this IEndpointRouteBuilder endpointRouteBuilder)
        {
            var staticFileOptions = new StaticFileOptions
            {
                FileProvider = new EmbeddedFileProvider(typeof(ClientCertificateManagementDefaults).Assembly, typeof(ClientCertificateManagementDefaults).Namespace),
                HttpsCompression = HttpsCompressionMode.Compress,
                RequestPath = ClientCertificateManagementDefaults.ManagementPortalAssetsUri
            };

            return endpointRouteBuilder
                .CreateApplicationBuilder()
                .Use(async (context, continuation) =>
                {
                    // unset endpoint or else StaticFileMiddleware will refuse to process
                    // https://github.com/dotnet/aspnetcore/issues/24252
                    context.SetEndpoint(null);
                    await continuation().ConfigureAwait(false);
                })
                .UseStaticFiles(staticFileOptions)
                .Build();
        }
    }
}