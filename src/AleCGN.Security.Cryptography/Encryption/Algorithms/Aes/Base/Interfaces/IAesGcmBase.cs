using System;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public interface IAesGcmBase : IEncryptionOperations, IDisposable
    {
        void SetOrUpdateKey(byte[] key);

        void SetOrUpdateKey(string encodedKey);
    }
}
