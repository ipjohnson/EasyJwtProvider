namespace EasyJwtProvider
{
    /// <summary>
    /// Request to refresh an expired token
    /// </summary>
    public class RefreshTokenRequest
    {
        /// <summary>
        /// Access Token
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Refresh token
        /// </summary>
        public string RefreshToken { get; set; }
    }
}
