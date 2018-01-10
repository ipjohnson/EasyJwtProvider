using System.Collections.Generic;
using System.IO;
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
    public class RefreshTokenTests
    {

        #region Form Encoding

        [Theory]
        [AutoData]
        public void Html_Form_Auth_Refresh_Valid(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.HasFormContentType.Returns(true);
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var signCredentials = SigningCredentials();

            var providerOptions = new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult<AuthenticationResult>(true);
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

            context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
            {
                { "grant_type", "refresh_token" },
                { "access_token", token.access_token },
                { "refresh_token", token.refresh_token }
            });

            outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var task2 = middleware.Execute(context, () => Task.FromResult(0));

            task2.Wait();

            var token2 = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token2);
            Assert.False(string.IsNullOrEmpty(token2.access_token));
            Assert.False(string.IsNullOrEmpty(token2.refresh_token));

            Assert.NotEqual(token.access_token, token2.access_token);
            Assert.NotEqual(token.refresh_token, token2.refresh_token);
        }

        #endregion

        #region Json encoding
        
        [Theory]
        [AutoData]
        public void Json_Data_Auth_Refresh_Valid(HttpContext context)
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

            context.Request.Body = new { grant_type = "refresh_token", token.access_token, token.refresh_token }.SerializeToStream();

            outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var task2 = middleware.Execute(context, () => Task.FromResult(0));

            task2.Wait();

            var token2 = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token2);
            Assert.False(string.IsNullOrEmpty(token2.access_token));
            Assert.False(string.IsNullOrEmpty(token2.refresh_token));

            Assert.NotEqual(token.access_token, token2.access_token);
            Assert.NotEqual(token.refresh_token, token2.refresh_token);
        }

        #endregion

        #region custom path

        [Theory]
        [AutoData]
        public void Html_Form_Auth_Refresh_Valid_Separate_Path(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.HasFormContentType.Returns(true);
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var signCredentials = SigningCredentials();

            var providerOptions = new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult<AuthenticationResult>(true);
            }, signCredentials)
            {
                RefreshTokenOptions = new JwtRefreshTokenOptions(signCredentials, claims => Task.FromResult("Some Salt"))
                {
                    RefreshPath = "/token-refresh"
                }
            };

            var middleware = new JwtMiddleware(providerOptions, null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            var token = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token);
            Assert.False(string.IsNullOrEmpty(token.access_token));
            Assert.False(string.IsNullOrEmpty(token.refresh_token));

            context.Request.Path = "/token-refresh";
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
            {
                { "access_token", token.access_token },
                { "refresh_token", token.refresh_token }
            });

            outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var task2 = middleware.Execute(context, () => Task.FromResult(0));

            task2.Wait();

            var token2 = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token2);
            Assert.False(string.IsNullOrEmpty(token2.access_token));
            Assert.False(string.IsNullOrEmpty(token2.refresh_token));

            Assert.NotEqual(token.access_token, token2.access_token);
            Assert.NotEqual(token.refresh_token, token2.refresh_token);
        }
        
        [Theory]
        [AutoData]
        public void Json_Data_Auth_Refresh_Valid_Seperate_Path(HttpContext context)
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
                {
                    RefreshPath = "/token-refresh"
                }
            };

            var middleware = new JwtMiddleware(providerOptions, null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            var token = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token);
            Assert.False(string.IsNullOrEmpty(token.access_token));
            Assert.False(string.IsNullOrEmpty(token.refresh_token));

            context.Request.Path = "/token-refresh";
            context.Request.Body = new { token.access_token, token.refresh_token }.SerializeToStream();

            outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var task2 = middleware.Execute(context, () => Task.FromResult(0));

            task2.Wait();

            var token2 = outstream.DeserializeFromMemoryStream<TokenClass>();

            Assert.NotNull(token2);
            Assert.False(string.IsNullOrEmpty(token2.access_token));
            Assert.False(string.IsNullOrEmpty(token2.refresh_token));

            Assert.NotEqual(token.access_token, token2.access_token);
            Assert.NotEqual(token.refresh_token, token2.refresh_token);
        }


        #endregion

        private SigningCredentials SigningCredentials()
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Test Secret Blah Blah"));

            return new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        }
    }
}
