using Microsoft.AspNetCore.Authentication.Digest;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.AspNetCore.Builder
{
    public static class DigestAppBuilderExtension
    {
        public static IApplicationBuilder UseDigestAuthentication(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<DigestAuthenticationMiddleware>();
        }

        public static IApplicationBuilder UseDigestAuthentication(this IApplicationBuilder app, DigestAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<DigestAuthenticationMiddleware>(Options.Create(options));
        }
    }
}
