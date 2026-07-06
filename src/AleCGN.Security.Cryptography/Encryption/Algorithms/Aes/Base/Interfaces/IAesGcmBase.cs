using System;
using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public interface IAesGcmBase : IEncryptionOperations, IDisposable
    {
        byte[] EncryptData(byte[] data, byte[] associatedData);

        string EncryptText(string text, byte[] associatedData);

        byte[] DecryptData(byte[] encryptedDataWithMetadata, byte[] associatedData);

        string DecryptText(string encryptedTextWithMetadata, byte[] associatedData);

        Task<byte[]> EncryptDataAsync(byte[] data, byte[] associatedData, CancellationToken cancellationToken = default);

        Task<string> EncryptTextAsync(string text, byte[] associatedData, CancellationToken cancellationToken = default);

        Task<byte[]> DecryptDataAsync(byte[] encryptedDataWithMetadata, byte[] associatedData, CancellationToken cancellationToken = default);

        Task<string> DecryptTextAsync(string encryptedTextWithMetadata, byte[] associatedData, CancellationToken cancellationToken = default);

        void SetOrUpdateKey(byte[] key);

        void SetOrUpdateKey(string encodedKey);
    }
}
