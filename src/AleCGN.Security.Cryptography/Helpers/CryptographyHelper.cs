using System.Security.Cryptography;

namespace AleCGN.Security.Cryptography.Helpers
{
    internal static class CryptographyHelper
    {
        internal static byte[] GenerateSecureRandomBytes(int length)
        {
            var randomBytes = new byte[length];

            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                rngCryptoServiceProvider.GetBytes(randomBytes);
            }

            return randomBytes;
        }
    }
}
