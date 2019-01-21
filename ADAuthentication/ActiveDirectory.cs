using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace ADAuthentication
{
    /// <summary>
    /// A class for looking up and authenticating users against an Active Directory domain.
    /// </summary>
    public static class ActiveDirectory
    {
        private const string DIRECTORY_USER_SEARCH_QUERY = "(&(objectClass=user)(objectCategory=user)(sAMAccountName={0}))";
        private const string DIRECTORY_GROUP_SEARCH_QUERY_TYPE_UNFILTERED = "(&(objectClass=group)(objectCategory=group)(objectSid={0}))";
        private const string DIRECTORY_GROUP_SEARCH_QUERY_TYPE_FILTERED = "(&(objectClass=group)(objectCategory=group)(objectSid={0})(groupType={1}))";
        private static Regex ldapErrorCodeCapture = new Regex(@", data (\w+),", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline);
        private static readonly string[] userPropertiesToLoad = new string[] { "displayName", "objectSid", "sAMAccountName" };
        private static readonly string[] groupPropertiesToLoad = new string[] { "sAMAccountName", "groupType" };
        private static readonly string[] groupPropertiesToRefreshCache = new string[] { "tokenGroups" };

        /// <summary>
        /// Looks up a user by their sAMAccountName.
        /// </summary>
        /// <param name="sAMAccountName">The sAMAccountName to lookup.</param>
        /// <param name="groupType">The group type to return for this user. By default, Global - Security is used.</param>
        /// <returns>A UserInfo instance for the first user found or null if no user was found.</returns>
        public static UserInfo? FindUser(string sAMAccountName, ActiveDirectoryGroupType groupType = ActiveDirectoryGroupType.SecurityGroup | ActiveDirectoryGroupType.GlobalScope)
        {
            using (DirectorySearcher directorySearcher = new DirectorySearcher(string.Format(DIRECTORY_USER_SEARCH_QUERY, sAMAccountName), userPropertiesToLoad))
            {
                SearchResult result = directorySearcher.FindOne();
                if (result != null)
                {
                    DirectoryEntry userEntry = result.GetDirectoryEntry();
                    return new UserInfo(
                        new SecurityIdentifier((byte[])userEntry.Properties["objectSid"][0], 0).Value,
                        (string)userEntry.Properties["sAMAccountName"][0],
                        (string)userEntry.Properties["displayName"][0],
                        GetUsersGroups(userEntry, groupType).ToArray()
                        );
                }
                else
                    return null;
            }
        }

        /// <summary>
        /// Transforms a UserInfo structure into a ClaimsIdentity for ASP.Net Authentication.
        /// </summary>
        /// <param name="user">The UserInfo structure to transform.</param>
        /// <returns>A ClaimsIdentity representation of a UserInfo structure.</returns>
        public static ClaimsIdentity GetUserClaimsIdentity(UserInfo user)
        {
            List<Claim> claims = new List<Claim>();

            claims.Add(new Claim(ClaimTypes.Sid, user.Sid)); // Sid
            claims.Add(new Claim(ClaimTypes.Name, user.Username)); // Username
            claims.Add(new Claim("DisplayName", user.DisplayName)); // Display Name
            claims.AddRange(user.Groups.Select(a => new Claim(ClaimTypes.Role, a))); // Groups

            return new ClaimsIdentity(claims, "Basic");
        }

        /// <summary>
        /// Validates a username and password against the Active Directory domain.
        /// </summary>
        /// <param name="domain">The domain to authenticate against.</param>
        /// <param name="username">The username to check.</param>
        /// <param name="password">The password to check.</param>
        /// <returns>The status returned by the domain controller.</returns>
        public static AccountAuthenticationResponse Authenticate(string domain, string username, string password)
        {
            try
            {
                using (LdapConnection connection = new LdapConnection(domain) { Credential = new NetworkCredential(username, password) })
                {
                    connection.Bind();
                }
                return AccountAuthenticationResponse.Success;
            }
            catch (LdapException ex)
            {
                string errorCode = ldapErrorCodeCapture.Match(ex.ServerErrorMessage).Groups[1].Value;
                switch (errorCode.ToUpperInvariant())
                {
                    case "525":
                        {
                            return AccountAuthenticationResponse.NotFound;
                        }

                    case "52E":
                        {
                            return AccountAuthenticationResponse.InvalidCredentials;
                        }

                    case "530":
                        {
                            return AccountAuthenticationResponse.LoginNotPermittedTime;
                        }

                    case "531":
                        {
                            return AccountAuthenticationResponse.LoginNotPermittedWorkstation;
                        }

                    case "532":
                        {
                            return AccountAuthenticationResponse.PasswordExpired;
                        }

                    case "533":
                        {
                            return AccountAuthenticationResponse.AccountDisabled;
                        }

                    case "701":
                        {
                            return AccountAuthenticationResponse.AccountExpired;
                        }

                    case "773":
                        {
                            return AccountAuthenticationResponse.ResetPasswordRequired;
                        }

                    case "775":
                        {
                            return AccountAuthenticationResponse.AccountLocked;
                        }
                }
            }

            // If we reached this point, we encountered an unknown condition.
            return AccountAuthenticationResponse.Unknown;
        }

        /// <summary>
        /// Gets the user's assigned groups.
        /// </summary>
        /// <param name="userEntry">A DirectoryEntry for the user to get groups for.</param>
        /// <param name="groupType">The group type to filter by.</param>
        /// <returns>An array of strings with the sAMAccountName of the groups assigned to this user and group type.</returns>
        private static string[] GetUsersGroups(DirectoryEntry userEntry, ActiveDirectoryGroupType groupType = ActiveDirectoryGroupType.SecurityGroup | ActiveDirectoryGroupType.GlobalScope)
        {
            List<string> groupMembership = new List<string>();

            userEntry.RefreshCache(groupPropertiesToRefreshCache);
            using (DirectorySearcher sidSearcher = new DirectorySearcher(string.Empty, groupPropertiesToLoad))
            {
                foreach (SecurityIdentifier tokenGroupSid in userEntry.Properties["tokenGroups"].Cast<byte[]>().Select(tokenGroupSidBytes => new SecurityIdentifier(tokenGroupSidBytes, 0)))
                {
                    if (groupType == ActiveDirectoryGroupType.None)
                        sidSearcher.Filter = string.Format(DIRECTORY_GROUP_SEARCH_QUERY_TYPE_UNFILTERED, tokenGroupSid.Value);
                    else
                        sidSearcher.Filter = string.Format(DIRECTORY_GROUP_SEARCH_QUERY_TYPE_FILTERED, tokenGroupSid.Value, (int)groupType);

                    SearchResult sidResult = sidSearcher.FindOne();
                    if (sidResult != null)
                    {
                        string gName = (string)sidResult.Properties["sAMAccountName"][0];
                        ActiveDirectoryGroupType gType = (ActiveDirectoryGroupType)sidResult.Properties["groupType"][0];
                        groupMembership.Add(gName);
                    }
                }
            }

            return groupMembership.ToArray();
        }
    }
}
