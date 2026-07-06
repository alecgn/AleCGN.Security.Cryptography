using System.Security.Cryptography;

namespace AleCGN.Security.Cryptography.Helpers
{
    public static class CryptographyHelper
    {
#if NETSTANDARD2_0
        // RandomNumberGenerator implementations are thread-safe; a single shared
        // instance avoids the cost of creating/disposing one per call.
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
#endif

        public static byte[] GenerateSecureRandomBytes(int length)
        {
            var randomBytes = new byte[length];

#if NETSTANDARD2_0
            _randomNumberGenerator.GetBytes(randomBytes);
#else
            RandomNumberGenerator.Fill(randomBytes);
#endif

            return randomBytes;
        }
    }
}
