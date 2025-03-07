﻿using AleCGN.Security.Cryptography.Constants;

namespace AleCGN.Security.Cryptography
{
    public enum SymmetricKeySizes
    {
        KeySize128Bits = 128,
        KeySize192Bits = 192,
        KeySize256Bits = 256
    }

    internal static class SymmetricKeySizesExtensions
    {
        internal static int ToBytesSize(this SymmetricKeySizes keySize)
            => (int)keySize / ConstantValues.BitsPerByte;
    }
}
