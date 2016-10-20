using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Digest
{
    public class DigestAuthenticationMiddleware : AuthenticationMiddleware<DigestAuthenticationOptions>
    {
        private readonly IMemoryCache _memoryCache;
        public DigestAuthenticationMiddleware(
            RequestDelegate next,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            IOptions<DigestAuthenticationOptions> options,
            IMemoryCache memoryCache)
            : base(next, options, loggerFactory, encoder)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            if (encoder == null)
            {
                throw new ArgumentNullException(nameof(encoder));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            _memoryCache = memoryCache;
        }
        protected override AuthenticationHandler<DigestAuthenticationOptions> CreateHandler()
        {
            return new DigestAuthenticationHandler(_memoryCache);
        }
    }
}
