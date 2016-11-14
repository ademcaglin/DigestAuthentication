using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication.Digest;

namespace Microsoft.AspNetCore.Builder
{
    public class DigestAuthenticationOptions : AuthenticationOptions
    {
        public string AppId { get; set; }

        public string SecretKey { get; set; }
        
        public IDigestUserService UserService { get; set; }      

        public DigestAuthenticationOptions()
        {
            AuthenticationScheme = DigestAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
