using System.Collections.Generic;
using System.Security.Claims;

namespace EasyJwtProvider
{
    /// <summary>
    /// Authentication result
    /// </summary>
    public class AuthenticationResult
    {
        /// <summary>
        /// Username that was authenticated
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Tenant the user was in
        /// </summary>
        public string Tenant { get; set; }

        /// <summary>
        /// Was the user authenticated
        /// </summary>
        public bool Authenticated { get; set; }

        /// <summary>
        /// Claims to add to JWT
        /// </summary>
        public IEnumerable<Claim> Claims { get; set; }

        /// <summary>
        /// Implicitly convert bool to authentication result
        /// </summary>
        /// <param name="authenticated"></param>
        public static implicit operator AuthenticationResult(bool authenticated)
        {
            return new AuthenticationResult { Authenticated = authenticated};
        }
    }
}
