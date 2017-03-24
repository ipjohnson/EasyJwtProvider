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
    /// Options class for configuring JWT provider
    /// </summary>
    public class JwtProviderOptions
    {
        /// <summary>
        /// Default constructor must provide method to authenticate user
        /// </summary>
        /// <param name="authenticateUser">Func that takes provider, username, password and returns an enumerable if valid, null if not</param>
        /// <param name="signingCredentials">credentials for signing jwt</param>
        public JwtProviderOptions(Func<AuthenticationRequest, Task<AuthenticationResult>> authenticateUser, SigningCredentials signingCredentials)
        {
            if (authenticateUser == null)
            {
                throw new ArgumentNullException(nameof(authenticateUser));
            }

            AuthenticateUser = authenticateUser;
            SigningCredentials = signingCredentials;
        }

        /// <summary>
        /// Path for authenticating
        /// </summary>
        public string AuthenticatePath { get; set; } = "/token";

        /// <summary>
        /// Issuer that will be used in the token
        /// </summary>
        public string Issuer { get; set; } = "Unknown";

        /// <summary>
        /// Audience for ticket
        /// </summary>
        public string Audience { get; set; } = "Unknown";

        /// <summary>
        /// Expiration, default 15 minutes
        /// </summary>
        public TimeSpan Expiration { get; set; } = new TimeSpan(0, 15, 0);

        /// <summary>
        /// Signing credentials
        /// </summary>
        public SigningCredentials SigningCredentials { get; }

        /// <summary>
        /// Process application/json token requests
        /// </summary>
        public bool ProcessJsonRequest { get; set; } = true;

        /// <summary>
        /// Method for authenticating users
        /// </summary>
        public Func<AuthenticationRequest, Task<AuthenticationResult>> AuthenticateUser { get; }

        /// <summary>
        /// Func to generate unique jti field, by default no jti is included
        /// </summary>
        public Func<IServiceProvider, string, Task<string>> JtiGenerator { get; set; } = (provider, s) => Task.FromResult(Guid.NewGuid().ToString());

        /// <summary>
        /// Configuration information for refreshing tokens
        /// </summary>
        public JwtRefreshTokenOptions RefreshTokenOptions { get; set; }

        /// <summary>
        /// String that is expected in the authentication request payload, default is "username" other options could be client_id
        /// </summary>
        public string UsernameString { get; set; } = "username";

        /// <summary>
        /// String that is expected in the authentication request payload, default is "username" other options could be client_secret
        /// </summary>
        public string PasswordString { get; set; } = "password";

        /// <summary>
        /// Optional string that can be in the authentication request payload, default is tenant
        /// </summary>
        public string TenantString { get; set; } = "tenant";

        /// <summary>
        /// When true "sub" is used as the property name in the JWT vs. http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier
        /// </summary>
        public bool UseSubForUsername { get; set; } = true;
    }
}
