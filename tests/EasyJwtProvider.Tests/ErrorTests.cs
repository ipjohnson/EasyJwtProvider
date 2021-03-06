﻿using System.Collections.Generic;
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
    public class ErrorTests
    {
        [Theory]
        [AutoData]
        public void Invalid_MethodType(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Get;
            context.Request.HasFormContentType.Returns(true);
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = new JwtMiddleware(new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult<AuthenticationResult>(true);
            }, SigningCredentials()),
            null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(400, context.Response.StatusCode);
        }

        [Theory]
        [AutoData]
        public void Invalid_ContentType(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.ContentType = "something-else";

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = new JwtMiddleware(new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult<AuthenticationResult>(true);
            }, SigningCredentials()),
            null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(400, context.Response.StatusCode);

        }

        [Theory]
        [AutoData]
        public void Invalid_GrantType_Form_Content(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.HasFormContentType.Returns(true);
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "grant_type", "something-else" }, { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = new JwtMiddleware(new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult<AuthenticationResult>(true);
            }, SigningCredentials()),
            null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(400, context.Response.StatusCode);

            var responseString = Encoding.UTF8.GetString(outstream.ToArray());

            Assert.Contains("grant_type", responseString);
            Assert.Contains("something-else", responseString);
        }

        [Theory]
        [AutoData]
        public void Invalid_GrantType_Json_Data(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.ContentType = "application/json";
            context.Request.Body = new { grant_type= "something-else", username = "user", password = "pass" }.SerializeToStream();

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = 
                new JwtMiddleware(new JwtProviderOptions(request => Task.FromResult<AuthenticationResult>(true), SigningCredentials()), null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(400, context.Response.StatusCode);

            var responseString = Encoding.UTF8.GetString(outstream.ToArray());

            Assert.Contains("grant_type", responseString);
            Assert.Contains("something-else", responseString);
        }

        [Theory]
        [AutoData]
        public void Invalid_UsernamePassword(HttpContext context)
        {
            context.Request.Path = "/token";
            context.Request.Method = HttpMethods.Post;
            context.Request.HasFormContentType.Returns(true);
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = new JwtMiddleware(new JwtProviderOptions(request =>
            {
                Assert.Equal("user", request.Username);
                Assert.Equal("pass", request.Password);

                return Task.FromResult<AuthenticationResult>(false);
            }, SigningCredentials()),
            null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(401, context.Response.StatusCode);

            var responseString = Encoding.UTF8.GetString(outstream.ToArray());

            Assert.Contains("username", responseString);
            Assert.Contains("password", responseString);
        }
        
        [Theory]
        [AutoData]
        public void Inavlid_Token_Refresh_Invalid_Method(HttpContext context)
        {
            context.Request.Path = "/token-refresh";
            context.Request.Method = HttpMethods.Get;
            context.Request.HasFormContentType.Returns(true);
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware = 
                new JwtMiddleware(
                    new JwtProviderOptions(request => Task.FromResult<AuthenticationResult>(true), SigningCredentials())
                    {
                        RefreshTokenOptions = new JwtRefreshTokenOptions(SigningCredentials(),claims => Task.FromResult("salt"))
                        {
                            RefreshPath = "/token-refresh"
                        }
                    }, null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(400, context.Response.StatusCode);
        }


        [Theory]
        [AutoData]
        public void Inavlid_Token_Refresh_Invalid_Content_Type(HttpContext context)
        {
            context.Request.Path = "/token-refresh";
            context.Request.Method = HttpMethods.Post;
            context.Request.HasFormContentType.Returns(false);
            context.Request.ContentType = "application/somethingElse";
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues> { { "username", "user" }, { "password", "pass" } });

            var outstream = new MemoryStream();

            context.Response.Body.Returns(outstream);

            var middleware =
                new JwtMiddleware(
                    new JwtProviderOptions(request => Task.FromResult<AuthenticationResult>(true), SigningCredentials())
                    {
                        RefreshTokenOptions = new JwtRefreshTokenOptions(SigningCredentials(), claims => Task.FromResult("salt"))
                        {
                            RefreshPath = "/token-refresh"
                        }
                    }, null);

            var task = middleware.Execute(context, () => Task.FromResult(0));

            task.Wait();

            Assert.Equal(400, context.Response.StatusCode);
        }

        private SigningCredentials SigningCredentials()
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Test Secret Blah Blah"));

            return new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        }
    }
}
