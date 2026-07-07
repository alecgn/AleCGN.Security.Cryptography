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

        /// <summary>
        /// Compares two byte arrays in an amount of time which depends only on their length,
        /// preventing timing attacks when comparing hashes, MACs or derived keys.
        /// </summary>
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
#if NETSTANDARD2_0
            if (left is null || right is null || left.Length != right.Length)
            {
                return false;
            }

            var difference = 0;

            for (var i = 0; i < left.Length; i++)
            {
                difference |= left[i] ^ right[i];
            }

            return difference == 0;
#else
            return left != null && right != null && CryptographicOperations.FixedTimeEquals(left, right);
#endif
        }
    }
}
