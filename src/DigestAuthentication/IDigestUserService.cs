using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Digest
{
    public interface IDigestUserService
    {
        string GetPassword(string userName);

        IEnumerable<Claim> GetClaims(string userName);
    }
}
