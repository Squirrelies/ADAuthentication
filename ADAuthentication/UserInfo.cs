namespace ADAuthentication
{
    /// <summary>
    /// A representation of important details for a user.
    /// </summary>
    public readonly struct UserInfo
    {
        /// <summary>
        /// The user's Security IDentifier (SID).
        /// </summary>
        public readonly string Sid;

        /// <summary>
        /// The user's username.
        /// </summary>
        public readonly string Username;

        /// <summary>
        /// The user's display name.
        /// </summary>
        public readonly string DisplayName;

        /// <summary>
        /// The user's groups. The groups shown are dependent upon the group type given during ADAuthenticationOptions configuration.
        /// </summary>
        public readonly string[] Groups;

        /// <summary>
        /// Creates a UserInfo structure.
        /// </summary>
        /// <param name="sid">The user's Security IDentifier (SID).</param>
        /// <param name="username">The user's username.</param>
        /// <param name="displayName">The user's display name.</param>
        /// <param name="globalSecurityGroups">The user's groups. The groups shown are dependent upon the group type given during ADAuthenticationOptions configuration.</param>
        public UserInfo(string sid, string username, string displayName, params string[] globalSecurityGroups)
        {
            this.Sid = sid;
            this.Username = username;
            this.DisplayName = displayName;
            this.Groups = globalSecurityGroups;
        }
    }
}
