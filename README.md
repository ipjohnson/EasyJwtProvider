# EasyJwtProvider
JWT provider for ASP.Net Core

This is a very basic JWT provider  inspired by [SimpleTokenProvider](https://github.com/nbarbettini/SimpleTokenProvider) with some refactoring and access to the HttpContext.

```
app.UseJwtProvider(new JwtOptions(AuthenticateFunction));

app.UseMvc();

private async Task<AuthenticationResult> AuthenticateFunction(AuthenticationRequest request)
{
    return new AuthenticationResult { Authenticated = true };
}

```

[![Build status](https://ci.appveyor.com/api/projects/status/ni4e1w597vtekm1u?svg=true)](https://ci.appveyor.com/project/ipjohnson/easyjwtprovider) [![Build Status](https://travis-ci.org/ipjohnson/EasyJwtProvider.svg?branch=master)](https://travis-ci.org/ipjohnson/EasyJwtProvider) [![Coverage Status](https://coveralls.io/repos/github/ipjohnson/EasyJwtProvider/badge.svg?branch=master)](https://coveralls.io/github/ipjohnson/EasyJwtProvider?branch=master)


