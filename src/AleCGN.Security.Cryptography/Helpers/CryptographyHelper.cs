using System.Security.Cryptography;

namespace AleCGN.Security.Cryptography.Helpers
{
    public static class CryptographyHelper
    {
        public static byte[] GenerateSecureRandomBytes(int length)
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
