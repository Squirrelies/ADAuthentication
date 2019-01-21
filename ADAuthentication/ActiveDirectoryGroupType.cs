using System;

namespace ADAuthentication
{
    /// <summary>
    /// Group types.
    /// </summary>
    [Flags]
    public enum ActiveDirectoryGroupType : int
    {
        /// <summary>
        /// No filter.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Built-in/System created.
        /// </summary>
        SystemCreated = 0x00000001,

        /// <summary>
        /// Global scope.
        /// </summary>
        GlobalScope = 0x00000002,

        /// <summary>
        /// Domain scope.
        /// </summary>
        DomainLocalScope = 0x00000004,

        /// <summary>
        /// Universal scope.
        /// </summary>
        UniversalScope = 0x00000008,

        /// <summary>
        /// Security group.
        /// </summary>
        SecurityGroup = unchecked((int)0x80000000)
    }
}
