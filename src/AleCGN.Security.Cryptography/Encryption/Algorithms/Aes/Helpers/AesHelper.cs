using AleCGN.Security.Cryptography.Resources;
using System;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes.Helpers
{
    internal static class AesHelper
    {
        internal static void ValidateAESKey(byte[] key, AesKeySizes expectedAesKeySize)
        {
            if (key is null || key.Length != expectedAesKeySize.ToBytesSize())
            {
                throw new ArgumentException(LibraryResources.Validation_AESKey, nameof(key));
            }
        }
    }
}
