using DigestAuthentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Digest
{
    internal class DigestAuthenticationHandler : AuthenticationHandler<DigestAuthenticationOptions>
    {
        private readonly IMemoryCache _memoryCache;

        public DigestAuthenticationHandler(IMemoryCache memoryCache)
        {
            _memoryCache = memoryCache;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var authorization = Request.Headers["authorization"];
            if (string.IsNullOrEmpty(authorization))
            {
                return AuthenticateResult.Skip();
            }
            var valid = Validate(Request);

            if (valid)
            {
                var principal = new ClaimsPrincipal(new ClaimsIdentity("Digest"));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");

        }

        protected override Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            Response.StatusCode = 401;
            var WWWAuthenticate = "Digest realm=\"DigestRealm\",";
            WWWAuthenticate += "qop=\"auth\",";
            WWWAuthenticate += "nonce=\""+ GenerateNonce() +"\",";
            Response.Headers.Append(HeaderNames.WWWAuthenticate, WWWAuthenticate);
            return Task.FromResult(false);
        }

        private bool Validate(HttpRequest request)
        {
            var header = request.Headers["authorization"];
            var authenticationHeader = AuthenticationHeaderValue.Parse(header);
            if (Options.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                var dict = GetHeaderDictionary(authenticationHeader.Parameter, request.Method);
                string nonce = dict["nonce"];
                var nonceInMemory = _memoryCache.Get(nonce);
                if (nonceInMemory == null)
                {
                    return false;
                }
                var password = dict["username"];
                string ha1 = String.Format("{0}:{1}:{2}",
                                        dict["username"],
                                        dict["realm"],
                                        password).ToMD5Hash();

                string ha2 = String.Format("{0}:{1}",
                                    dict["method"],
                                    dict["uri"]).ToMD5Hash();

                string computedResponse = String
                              .Format("{0}:{1}:{2}:{3}:{4}:{5}",
                                    ha1,
                                    dict["nonce"],
                                    dict["nc"],
                                    dict["cnonce"],
                                    "auth",
                                    ha2).ToMD5Hash();

                if (string.CompareOrdinal(dict["response"], computedResponse) == 0)
                {
                    return true;
                }
            }

            return false;
        }

        private string GenerateNonce()
        {
            byte[] bytes = new byte[16];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            string nonce = bytes.ToMD5Hash();
            _memoryCache.Set(nonce, DateTimeOffset.UtcNow.AddSeconds(600));
            
            return nonce;
        }

        private Dictionary<string, string> GetHeaderDictionary(string header, string method)
        {
            var dictionary = new Dictionary<string, string>();
            string keyValuePairs = header.Replace("\"", String.Empty);
            dictionary.Add("method", method);
            foreach (string keyValuePair in keyValuePairs.Split(','))
            {
                int index = keyValuePair.IndexOf("=");
                string key = keyValuePair.Substring(0, index).Trim();
                string value = keyValuePair.Substring(index + 1);
                dictionary.Add(key, value);
            }
            return dictionary;
        }
    }
}
