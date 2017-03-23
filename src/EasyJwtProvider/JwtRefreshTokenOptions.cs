using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace EasyJwtProvider
{
    /// <summary>
    /// Options for setting up refresh token
    /// </summary>
    public class JwtRefreshTokenOptions
    {
        /// <summary>
        /// Default constrcutor
        /// </summary>
        /// <param name="signingCredentials">credentials used to sign the JWT refresh token</param>
        /// <param name="saltProvider">function that provides salt for refresh token provided a set of claims</param>
        public JwtRefreshTokenOptions(SigningCredentials signingCredentials, Func<Claim[], Task<string>> saltProvider)
        {
            if (signingCredentials == null)
            {
                throw new ArgumentNullException(nameof(signingCredentials));
            }

            if (saltProvider == null)
            {
                throw new ArgumentNullException(nameof(saltProvider));
            }

            SigningCredentials = signingCredentials;
            SaltProvider = saltProvider;
        }

        /// <summary>
        /// Credentials used to sign refresh token
        /// </summary>
        public SigningCredentials SigningCredentials { get; }

        /// <summary>
        /// Func used to provide salt
        /// </summary>
        public Func<Claim[], Task<string>> SaltProvider { get; }

        /// <summary>
        /// Window the access token is allowed to be refreshed in after it's expired
        /// </summary>
        public TimeSpan RefreshWindow { get; set; } = new TimeSpan(0, 15, 0);

        /// <summary>
        /// Url to refresh path, if null it's assumed the token url is used with a grant_type=refresh_token
        /// </summary>
        public string RefreshPath { get; set; }
        
        /// <summary>
        /// Provide method to check if principal should be refreshed
        /// </summary>
        public Func<HttpContext, ClaimsPrincipal, SecurityToken, Task<bool>> RefreshToken { get; set; }
    }
}
