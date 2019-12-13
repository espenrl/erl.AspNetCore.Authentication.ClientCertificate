using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace erl.AspNetCore.Authentication.ClientCertificate
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddClientCertificateManagementUiApi(this IServiceCollection services, Action<CertificateManagementUiOptions> configureOptions = null)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));

            services
                .AddOptions<CertificateManagementUiOptions>()
                .PostConfigure(configureOptions ?? (_ => { }));

            // setup management APIs
            services
                .AddControllers()
                .PartManager
                .ApplicationParts
                .Add(new AssemblyPart(typeof(ClientCertificateManagementDefaults).Assembly));

            return services;
        }

        public static AuthenticationBuilder AddCertificateAuthentication(this AuthenticationBuilder builder, Action<CertificateManagementValidationOptions> configureOptions = null)
        {
            if (builder == null) throw new ArgumentNullException(nameof(builder));

            static void ConfigureAuthorization(AuthorizationOptions options)
            {
                options.AddPolicy(
                    ClientCertificateManagementDefaults.ManageClientCertificatesPolicyName,
                    policyBuilder => policyBuilder.RequireRole(ClientCertificateManagementDefaults.ManageClientCertificatesRoleName));
            }

            static void ConfigureCertificateAuthentication(CertificateAuthenticationOptions options)
            {
                options.Events = new CertificateAuthenticationEvents();
                options.Events.OnCertificateValidated = async context =>
                {
                    var validationService = context
                        .HttpContext
                        .RequestServices
                        .GetService<IClientCertificateValidationService>();

                    var ctx = new ClientCertificateValidationContext();
                    await validationService
                        .ValidateCertificate(context.ClientCertificate, ctx)
                        .ConfigureAwait(false);

                    if (ctx.IsFail)
                    {
                        context.Fail(ctx.FailureMessage);
                        return;
                    }

                    // verify that IClientCertificateValidationService implementation behaves correctly
                    if (!ctx.IsSuccess)
                    {
                        context.Fail($"{validationService.GetType().FullName} is incorrectly implemented. It has to call Fail or Success on supplied context.");
                        return;
                    }

                    // success, set role claim
                    var claimsIdentity = context.Principal.Identities.Single();
                    claimsIdentity.Label = ctx.ClientCertificate.Description;
                    claimsIdentity.AddClaim(new Claim(
                        ClaimTypes.Role,
                        ctx.ClientCertificate.Role,
                        ClaimValueTypes.String,
                        context.Options.ClaimsIssuer));

                    context.Success();
                };
            }

            static bool ValidateCertificateManagementValidationOptions(CertificateManagementValidationOptions options)
            {
                return !options.SecurityClearanceRoles.IsEmpty; // empty role collection not allowed
            }

            builder.Services.TryAddScoped<ICertificateGenerator, DefaultCertificateGenerator>();
            builder.Services.TryAddScoped<IClientCertificateValidationService, DefaultClientCertificateValidationService>();
            builder.Services
                .AddOptions<CertificateManagementValidationOptions>()
                .PostConfigure(configureOptions ?? (_ => { }))
                .Validate(ValidateCertificateManagementValidationOptions);

            // set ASP.NET Core framework options
            builder.Services.PostConfigure<CertificateAuthenticationOptions>(CertificateAuthenticationDefaults.AuthenticationScheme, ConfigureCertificateAuthentication);
            builder.Services.PostConfigure<AuthorizationOptions>(ConfigureAuthorization);
            return builder;
        }
    }
}