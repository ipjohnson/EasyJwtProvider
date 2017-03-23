using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace EasyJwtProvider
{
    /// <summary>
    /// Represents an authentication request
    /// </summary>
    public class AuthenticationRequest
    {
        /// <summary>
        /// Http context
        /// </summary>
        public HttpContext HttpContext { get; set; }
        
        /// <summary>
        /// Username
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Password
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Tenant
        /// </summary>
        public string Tenant { get; set; }
    }
}
