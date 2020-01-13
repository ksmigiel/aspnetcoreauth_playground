using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace http_basic
{
    public class BasicAuthMiddleware : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public BasicAuthMiddleware(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return AuthenticateResult.Fail("Missing Authorization header!");
            }

            var authorizationHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            var credentialBytes = Convert.FromBase64String(authorizationHeader.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(":");

            if (credentials[0] == "admin" && credentials[1] == "qwe")
            {
                var claims = new[] { new Claim(ClaimTypes.Name, credentials[0]) };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
            }
            else
            {
                return AuthenticateResult.Fail("Ups, wrong username/password.");
            }
        }
    }
}
