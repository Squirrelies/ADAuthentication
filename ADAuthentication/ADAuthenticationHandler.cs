using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;

namespace ADAuthentication
{
    public class ADAuthenticationHandler : AuthenticationHandler<ADAuthenticationOptions>
    {
        private static readonly Encoding _enc = Encoding.GetEncoding("iso-8859-1");
        
        public ADAuthenticationHandler(IOptionsMonitor<ADAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }
        
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = $"Basic realm=\"{Options.Domain}\", charset=\"UTF-8\"";
            await base.HandleChallengeAsync(properties);
        }
        
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            UserInfo? user = null;
            AccountAuthenticationResponse authenticationResponse = AccountAuthenticationResponse.Unknown;

            string authHeader = Context.Request.Headers["Authorization"];
            if (authHeader != null && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                // Convert the base64 string to a byte array.
                byte[] encodedUsernamePassword = Convert.FromBase64String(authHeader.Substring(6).TrimEnd());

                // Transform the byte array into a string using the encoding defined in the HTTP specs.
                string[] usernamePassword = _enc.GetString(encodedUsernamePassword).Split(new char[1] { ':' }, 2, StringSplitOptions.None);

                // Lookup the user.
                user = ActiveDirectory.FindUser(usernamePassword[0], Options.GroupType);

                // If the user is not null, we found a match.
                if (user != null)
                {
                    // Attempt to validate the given credentials.
                    if ((authenticationResponse = ActiveDirectory.Authenticate(Options.Domain, usernamePassword[0], usernamePassword[1])) == AccountAuthenticationResponse.Success)
                    {
                        // Get a ClaimsIdentity based on this UserPrincipal.
                        ClaimsIdentity userCI = ActiveDirectory.GetUserClaimsIdentity(user.Value);

                        // Return successfully.
                        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(userCI), new AuthenticationProperties(), this.Scheme.Name)));
                    }
                }
            }

            // If we got down this far, we were not authorized for one reason or another.
            // This could mean one of the following: not found, expired, disabled, locked out, bad username or password.
            // You can check the user or authenticationResponse variables to see what happened.
            return Task.FromResult(AuthenticateResult.Fail("Invalid credentials."));
        }
    }
}
