using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Digest
{
    public class DigestAuthenticationDefaults
    {
        /// <summary>
        /// The default value used for HmacAuthenticationOptions.AuthenticationScheme
        /// </summary>
        public const string AuthenticationScheme = "Digest";
    }
}
