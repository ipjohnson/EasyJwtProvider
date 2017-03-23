# EasyJwtProvider
JWT provider for ASP.Net Core

This is a very basic JWT provider  inspired by [SimpleTokenProvider](https://github.com/nbarbettini/SimpleTokenProvider) with some refactoring and access to the HttpContext.

```
app.UseJwtProvider(new JwtOptions(AuthenticateFunction));

app.UseMvc();

private async Task<AuthenticationResult> AuthenticateFunction(AuthenticateRequest request)
{
    return new AuthenticationResult { Authenticated = true };
}

```
