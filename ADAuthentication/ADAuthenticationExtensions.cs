using Microsoft.AspNetCore.Authentication;
using System;

namespace ADAuthentication
{
    public static class ADAuthenticationExtensions
    {
        public static AuthenticationBuilder AddADAuthentication(this AuthenticationBuilder builder, Action<ADAuthenticationOptions> configureOptions = null) => builder.AddScheme<ADAuthenticationOptions, ADAuthenticationHandler>("ADAuthenticationScheme", "An implementation of Active Directory Authentication over WWW-Authenticate/Basic authentication.", configureOptions);
    }
}
