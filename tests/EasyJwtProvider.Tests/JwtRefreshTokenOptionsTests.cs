using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace EasyJwtProvider.Tests
{
    public class JwtRefreshTokenOptionsTests
    {
        [Fact]
        public void JwtRefreshTokenOptions_Null_Signing_Credentials()
        {
            Assert.Throws<ArgumentNullException>(() => new JwtRefreshTokenOptions(null, claims => Task.FromResult("")));
        }

        [Fact]
        public void JwtRefreshTokenOptions_Null_Salt()
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Test Secret Blah Blah"));

            var signingCred = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            Assert.Throws<ArgumentNullException>(() => new JwtRefreshTokenOptions(signingCred, null));
        }
    }
}
