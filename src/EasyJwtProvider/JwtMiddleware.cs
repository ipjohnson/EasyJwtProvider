using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EasyJwtProvider
{
    /// <summary>
    /// Middleware class
    /// </summary>
    public class JwtMiddleware
    {
        /// <summary>
        /// access_token
        /// </summary>
        protected const string AccessTokenStr = "access_token";

        /// <summary>
        /// refresh_token
        /// </summary>
        protected const string RefreshTokenStr = "refresh_token";

        /// <summary>
        /// Options for provider
        /// </summary>
        protected readonly JwtProviderOptions Options;

        /// <summary>
        /// Json serializer
        /// </summary>
        protected JsonSerializer Serializer;

        /// <summary>
        /// validation parameter used
        /// </summary>
        protected readonly TokenValidationParameters ValidationParameters;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="options"></param>
        /// <param name="validationParameters"></param>
        public JwtMiddleware(JwtProviderOptions options, TokenValidationParameters validationParameters)
        {
            Options = options;
            ValidationParameters = validationParameters ??
                                   new TokenValidationParameters
                                   {
                                       ValidIssuer = Options.Issuer,
                                       ValidateIssuer = true,
                                       ValidAudience = Options.Audience,
                                       ValidateAudience = true,
                                       IssuerSigningKey = Options.SigningCredentials.Key,
                                       ValidateLifetime = false
                                   };

            Serializer = new JsonSerializer();
        }

        /// <summary>
        /// Execute middleware
        /// </summary>
        /// <param name="context"></param>
        /// <param name="next"></param>
        /// <returns></returns>
        public virtual Task Execute(HttpContext context, Func<Task> next)
        {
            if (string.Compare(Options.AuthenticatePath, context.Request.Path, StringComparison.CurrentCultureIgnoreCase) == 0)
            {
                if (context.Request.Method != HttpMethods.Post)
                {
                    return ReturnInvalidRequest(context);
                }

                if (context.Request.HasFormContentType)
                {
                    return ProcessFormData(context, AccessTokenStr);
                }

                if (context.Request.ContentType.StartsWith("application/json", StringComparison.CurrentCultureIgnoreCase))
                {
                    return ProcessJsonData(context, AccessTokenStr);
                }

                return ReturnInvalidRequest(context);
            }

            if (Options.RefreshTokenOptions?.RefreshPath != null &&
                string.Compare(Options.RefreshTokenOptions.RefreshPath, context.Request.Path, StringComparison.CurrentCultureIgnoreCase) == 0)
            {
                if (context.Request.Method != HttpMethods.Post)
                {
                    return ReturnInvalidRequest(context);
                }

                if (context.Request.HasFormContentType)
                {
                    return ProcessFormData(context, RefreshTokenStr);
                }

                if (context.Request.ContentType.StartsWith("application/json", StringComparison.CurrentCultureIgnoreCase))
                {
                    return ProcessJsonData(context, RefreshTokenStr);
                }

                return ReturnInvalidRequest(context);
            }

            return next();
        }

        /// <summary>
        /// Process json data request
        /// </summary>
        /// <param name="context"></param>
        /// <param name="grantTypeString"></param>
        /// <returns></returns>
        protected virtual Task ProcessJsonData(HttpContext context, string grantTypeString)
        {
            using (var textReader = new StreamReader(context.Request.Body))
            {
                using (var jsonReader = new JsonTextReader(textReader))
                {
                    var dataObject = Serializer.Deserialize<JObject>(jsonReader);

                    var grantType = dataObject["grant_type"];

                    if (grantType != null)
                    {
                        grantTypeString = grantType.ToString();
                    }

                    if (grantTypeString == AccessTokenStr)
                    {
                        var authRequest = new AuthenticationRequest
                        {
                            Username = dataObject["username"]?.ToString(),
                            Password = dataObject["password"]?.ToString(),
                            Tenant = dataObject["tenant"]?.ToString()
                        };

                        return ProcessAuthenticationRequest(context, authRequest);
                    }

                    if (grantTypeString == RefreshTokenStr)
                    {
                        var refreshToken = new RefreshTokenRequest
                        {
                            AccessToken = dataObject[AccessTokenStr]?.ToString(),
                            RefreshToken = dataObject[RefreshTokenStr]?.ToString()
                        };

                        return ProcessRefreshAuthenticationRequest(context, refreshToken);
                    }

                    return UnknownGrantType(context, grantTypeString);
                }
            }
        }


        /// <summary>
        /// Process request with form encoding
        /// </summary>
        /// <param name="context"></param>
        /// <param name="grantTypeString"></param>
        /// <returns></returns>
        protected virtual Task ProcessFormData(HttpContext context, string grantTypeString)
        {
            var grantType = context.Request.Form["grant_type"];

            if (grantType.Count > 0)
            {
                grantTypeString = grantType[0];
            }

            if (grantTypeString == AccessTokenStr)
            {
                var authRequest = new AuthenticationRequest
                {
                    Username = context.Request.Form["username"],
                    Password = context.Request.Form["password"],
                    Tenant = context.Request.Form["tenant"]
                };

                return ProcessAuthenticationRequest(context, authRequest);
            }

            if (grantTypeString == RefreshTokenStr)
            {
                var refreshToken = new RefreshTokenRequest
                {
                    AccessToken = context.Request.Form[AccessTokenStr].ToString(),
                    RefreshToken = context.Request.Form[RefreshTokenStr].ToString()
                };

                return ProcessRefreshAuthenticationRequest(context, refreshToken);
            }

            return UnknownGrantType(context, grantTypeString);
        }

        /// <summary>
        /// Process authentication request
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authenticationRequest"></param>
        /// <returns></returns>
        protected virtual async Task ProcessAuthenticationRequest(HttpContext context, AuthenticationRequest authenticationRequest)
        {
            var authenticateResponse = await Options.AuthenticateUser(authenticationRequest);

            if (!authenticateResponse.Authenticated)
            {
                await ReturnUnauthorize(context);

                return;
            }

            if (string.IsNullOrEmpty(authenticateResponse.Username))
            {
                authenticateResponse.Username = authenticationRequest.Username;
            }

            if (string.IsNullOrEmpty(authenticateResponse.Tenant))
            {
                authenticateResponse.Tenant = authenticationRequest.Tenant;
            }

            var now = DateTime.UtcNow;

            var unixEpoch =
                ((int)now.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds).ToString();

            var claims =
                await GetClaims(context.RequestServices, authenticateResponse.Username, unixEpoch, authenticateResponse);

            await IssueJwt(context, claims, now);
        }

        /// <summary>
        /// Process a refresh authentication request
        /// </summary>
        /// <param name="context"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        protected virtual async Task ProcessRefreshAuthenticationRequest(HttpContext context, RefreshTokenRequest refreshToken)
        {
            try
            {
                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

                SecurityToken originalToken;

                var claimPrincipal = jwtSecurityTokenHandler.ValidateToken(refreshToken.AccessToken, ValidationParameters, out originalToken);

                var now = DateTime.UtcNow;
                var refresh = await AuthenticateRefreshToken(claimPrincipal, originalToken, refreshToken.RefreshToken, now);

                if (refresh && Options.RefreshTokenOptions.RefreshToken != null)
                {
                    refresh = await Options.RefreshTokenOptions.RefreshToken(context, claimPrincipal, originalToken);
                }

                if (refresh)
                {
                    var claims = claimPrincipal.Claims.ToList();

                    // generate new identifier for token
                    claims.RemoveAll(c => c.Type == JwtRegisteredClaimNames.Jti);
                    claims.Insert(0, new Claim(JwtRegisteredClaimNames.Jti, await Options.JtiGenerator(context.RequestServices, claimPrincipal.Identity.Name)));

                    await IssueJwt(context, claims.ToArray(), now);
                }
                else
                {
                    await ReturnUnauthorizedRefresh(context);
                }
            }
            catch (Exception)
            {
                await ReturnInvalidRequest(context);
            }
        }

        /// <summary>
        /// Authenticate refresh token
        /// </summary>
        /// <param name="claimPrincipal"></param>
        /// <param name="originalToken"></param>
        /// <param name="refreshToken"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        protected virtual async Task<bool> AuthenticateRefreshToken(ClaimsPrincipal claimPrincipal, SecurityToken originalToken, string refreshToken, DateTime now)
        {
            if (originalToken.ValidTo < now.Subtract(Options.RefreshTokenOptions.RefreshWindow))
            {
                return false;
            }

            return refreshToken == await GenerateRefreshToken(claimPrincipal.Claims.ToArray(), originalToken.Id);
        }

        /// <summary>
        /// Issue JWT
        /// </summary>
        /// <param name="context"></param>
        /// <param name="claims"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        protected virtual async Task IssueJwt(HttpContext context, Claim[] claims, DateTime now)
        {
            var token = new JwtSecurityToken(Options.Issuer,
                Options.Audience,
                claims,
                now,
                now.Add(Options.Expiration),
                Options.SigningCredentials);

            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);

            object responseObject;

            if (Options.RefreshTokenOptions == null)
            {
                responseObject = new
                {
                    access_token = encodedToken,
                    expires_in = (int)Options.Expiration.TotalSeconds
                };
            }
            else
            {
                var uniqueId = claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
                
                responseObject = new
                {
                    access_token = encodedToken,
                    expires_in = (int)Options.Expiration.TotalSeconds,
                    refresh_token = await GenerateRefreshToken(claims, uniqueId)
                };
            }

            context.Response.ContentType = "application/json";

            using (var textWriter = new StreamWriter(context.Response.Body))
            {
                using (var jsonWriter = new JsonTextWriter(textWriter))
                {
                    Serializer.Serialize(jsonWriter, responseObject);
                }
            }
        }

        /// <summary>
        /// Get claims
        /// </summary>
        /// <param name="serviceProvider"></param>
        /// <param name="username"></param>
        /// <param name="unixEpoch"></param>
        /// <param name="authenticate"></param>
        /// <returns></returns>
        protected virtual async Task<Claim[]> GetClaims(IServiceProvider serviceProvider, StringValues username, string unixEpoch, AuthenticationResult authenticate)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, await Options.JtiGenerator(serviceProvider, username)),
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Iat, unixEpoch, ClaimValueTypes.Integer64),
            };

            if (authenticate.Claims != null)
            {
                claims.AddRange(authenticate.Claims);
            }

            return claims.ToArray();
        }

        /// <summary>
        /// Generate a refresh token for a given set of claims and tokenId
        /// </summary>
        /// <param name="claims"></param>
        /// <param name="tokenId"></param>
        /// <returns></returns>
        protected virtual async Task<string> GenerateRefreshToken(Claim[] claims, string tokenId)
        {
            var salt = await Options.RefreshTokenOptions.SaltProvider(claims);

            var unencryptedbytes = Encoding.UTF8.GetBytes($"{tokenId}|{salt}");

            var signingCredentials = Options.RefreshTokenOptions.SigningCredentials;

            var cryptoFactory = signingCredentials.CryptoProviderFactory ?? CryptoProviderFactory.Default;

            var signatureProvider = cryptoFactory.CreateForSigning(signingCredentials.Key, signingCredentials.Algorithm);

            var signatureBytes = signatureProvider.Sign(unencryptedbytes);

            cryptoFactory.ReleaseSignatureProvider(signatureProvider);

            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// Return unauthorized result
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected virtual Task ReturnUnauthorize(HttpContext context)
        {
            context.Response.StatusCode = 400;

            return context.Response.WriteAsync("Invalid username/password");
        }

        /// <summary>
        /// Return unauthorized refresh
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected virtual Task ReturnUnauthorizedRefresh(HttpContext context)
        {
            context.Response.StatusCode = 400;

            return context.Response.WriteAsync("Unauthotized refresh");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected virtual Task ReturnInvalidRequest(HttpContext context)
        {
            context.Response.StatusCode = 400;

            return context.Response.WriteAsync("Inavlid request");
        }

        /// <summary>
        /// Return unknown grant type message
        /// </summary>
        /// <param name="context"></param>
        /// <param name="grantTypeString"></param>
        /// <returns></returns>
        protected virtual Task UnknownGrantType(HttpContext context, string grantTypeString)
        {
            context.Response.StatusCode = 400;

            return context.Response.WriteAsync($"Unknown grant_type: {grantTypeString}");
        }
    }
}
