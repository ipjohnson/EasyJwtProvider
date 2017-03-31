using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using SimpleFixture.NSubstitute;
using SimpleFixture.xUnit;
using Xunit;

namespace EasyJwtProvider.Tests
{
    [SubFixtureInitialize]
    public class AppBuilderExtensionsTests
    {
        [Fact]
        public void UseJwtProvider_Null_App()
        {
            Assert.Throws<ArgumentNullException>(() =>
                AppBuilderExtensions.UseJwtProvider(null, 
                    new JwtProviderOptions(request => Task.FromResult<AuthenticationResult>(true), SigningCredentials())));
        }

        [Theory]
        [AutoData]
        public void UseJwtProvider_Null_Options_Throws(IApplicationBuilder app)
        {
            Assert.Throws<ArgumentNullException>(() => app.UseJwtProvider(null));
        }

        [Theory]
        [AutoData]
        public void UseJwtProvider_Call_Use(IApplicationBuilder app)
        {
            app.UseJwtProvider(
                new JwtProviderOptions(request => Task.FromResult<AuthenticationResult>(true), SigningCredentials()));
            
            app.Received().Use(Arg.Any<Func<RequestDelegate,RequestDelegate>>());
        }
        
        private SigningCredentials SigningCredentials()
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Test Secret Blah Blah"));

            return new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        }
    }
}
