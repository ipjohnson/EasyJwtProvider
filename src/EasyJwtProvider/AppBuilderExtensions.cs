using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace EasyJwtProvider
{
    /// <summary>
    /// C# extension class for app builder
    /// </summary>
    public static class AppBuilderExtensions
    {
        /// <summary>
        /// Add JWT provider middleware. 
        /// </summary>
        /// <param name="appBuilder">app builder</param>
        /// <param name="options">jwt provider options</param>
        /// <param name="validationParameters">validate parameters to be used for refresh, can be null</param>
        /// <returns></returns>
        public static IApplicationBuilder UseJwtProvider(this IApplicationBuilder appBuilder, JwtProviderOptions options, TokenValidationParameters validationParameters = null)
        {
            if (appBuilder == null)
            {
                throw new ArgumentNullException(nameof(appBuilder));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return appBuilder.Use(new JwtMiddleware(options, validationParameters).Execute);
        }
    }
}
