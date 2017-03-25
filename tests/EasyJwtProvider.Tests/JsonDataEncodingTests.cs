using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using SimpleFixture.NSubstitute;
using SimpleFixture.xUnit;
using Xunit;

namespace EasyJwtProvider.Tests
{
    [SubFixtureInitialize]
    public class JsonDataEncodingTests
    {
        #region Form Tests
        [Theory]
        [AutoData]
        public void Valid_Json_Data_Auth_Request(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.ContentType = "application/json";
            context.Request.Body = new { username = "user", password = "pass" }.SerializeToStream();

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = new JwtMiddleware(new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult(new AuthenticationResult { Authenticated = true });
            }, SigningCredentials()),
            null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            var token = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token);
            Assert.NotNull(token.access_token);
            Assert.False(string.IsNullOrEmpty(token.access_token));
        }

        [Theory]
        [AutoData]
        public void Valid_Json_Data_Auth_Request_With_Refresh(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.ContentType = "application/json";
            context.Request.Body = new { username = "user", password = "pass" }.SerializeToStream();

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var signCredentials = SigningCredentials();

            var providerOptions = new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult(new AuthenticationResult { Authenticated = true });
            }, signCredentials)
            {
                RefreshTokenOptions = new JwtRefreshTokenOptions(signCredentials, claims => Task.FromResult("Some Salt"))
            };

            var middleware = new JwtMiddleware(providerOptions, null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            var token = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token);
            Assert.False(string.IsNullOrEmpty(token.access_token));
            Assert.False(string.IsNullOrEmpty(token.refresh_token));
        }

        #endregion


        private SigningCredentials SigningCredentials()
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Test Secret Blah Blah"));

            return new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        }
    }
}
