using System;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20
{
    public interface IChaCha20Poly1305 : IEncryptionOperations, IDisposable
    {
        byte[] EncryptData(byte[] data, byte[] associatedData);

        string EncryptText(string text, byte[] associatedData);

        byte[] DecryptData(byte[] encryptedDataWithMetadata, byte[] associatedData);

        string DecryptText(string encryptedTextWithMetadata, byte[] associatedData);

        void SetOrUpdateKey(byte[] key);

        void SetOrUpdateKey(string encodedKey);
    }
}
