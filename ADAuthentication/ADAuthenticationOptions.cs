using Microsoft.AspNetCore.Authentication;

namespace ADAuthentication
{
    public class ADAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Domain { get; set; }
        public ActiveDirectoryGroupType GroupType { get; set; }
    }
}
