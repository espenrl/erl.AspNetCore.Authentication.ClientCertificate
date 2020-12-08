using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;

namespace Example.HealthChecksUI
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        private static IHostBuilder CreateHostBuilder(string[] args)
        {
            static void ConfigureKestrel(KestrelServerOptions options)
            {
                options.ConfigureHttpsDefaults(o =>
                {
                    o.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    o.AllowAnyClientCertificate();
                });
            }

            return Host
                .CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder
                        .UseStartup<Startup>()
                        .ConfigureKestrel(ConfigureKestrel);
                });
        }
    }
}
