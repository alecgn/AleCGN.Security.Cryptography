namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    internal enum AesKeySizes
    {
        KeySize128Bits = SymmetricKeySizes.KeySize128Bits,
        KeySize192Bits = SymmetricKeySizes.KeySize192Bits,
        KeySize256Bits = SymmetricKeySizes.KeySize256Bits
    }

    internal static class AesKeySizesExtensions
    {
        public static int ToBytesSize(this AesKeySizes aesKeySize)
            => ((SymmetricKeySizes)aesKeySize).ToBytesSize();
    }
}
