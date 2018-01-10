using System;
using Xunit;

namespace EasyJwtProvider.Tests
{
    public class JwtProviderOptionsTests
    {
        [Fact]
        public void JwtProviderOptions_Null_Test()
        {
            Assert.Throws<ArgumentNullException>(() => new JwtProviderOptions(null, null));
        }
    }
}
