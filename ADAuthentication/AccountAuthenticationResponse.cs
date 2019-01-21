namespace ADAuthentication
{
    /// <summary>
    /// An enumeration of possible authentication results.
    /// </summary>
    public enum AccountAuthenticationResponse : uint
    {
        /// <summary>
        /// Successful authentication.
        /// </summary>
        Success = 0, // 0x0 (Assumed)

        /// <summary>
        /// User not found.
        /// </summary>
        NotFound = 1317, // 0x525

        /// <summary>
        /// Incorrect password.
        /// </summary>
        InvalidCredentials = 1326, // 0x52E

        /// <summary>
        /// Login is not permitted at this time.
        /// </summary>
        LoginNotPermittedTime = 1328, // 0x530

        /// <summary>
        /// Login is not premitted at this workstation.
        /// </summary>
        LoginNotPermittedWorkstation = 1329, // 0x531

        /// <summary>
        /// Password has expired.
        /// </summary>
        PasswordExpired = 1330, // 0x532

        /// <summary>
        /// User is disabled.
        /// </summary>
        AccountDisabled = 1331, // 0x533

        /// <summary>
        /// User has expired.
        /// </summary>
        AccountExpired = 1793, // 0x701

        /// <summary>
        /// Password reset is required.
        /// </summary>
        ResetPasswordRequired = 1907, // 0x773

        /// <summary>
        /// User is locked out.
        /// </summary>
        AccountLocked = 1909, // 0x775

        /// <summary>
        /// Unknown error.
        /// </summary>
        Unknown = uint.MaxValue // 0xFFFFFFFF (Assumed)
    }
}
