using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Encryption
{
    public interface IEncryptionOperations
    {
        byte[] EncryptData(byte[] data);

        string EncryptText(string text);

        byte[] DecryptData(byte[] encryptedData);

        string DecryptText(string encryptedText);

        Task<byte[]> EncryptDataAsync(byte[] data, CancellationToken cancellationToken = default);

        Task<string> EncryptTextAsync(string text, CancellationToken cancellationToken = default);

        Task<byte[]> DecryptDataAsync(byte[] encryptedData, CancellationToken cancellationToken = default);

        Task<string> DecryptTextAsync(string encryptedText, CancellationToken cancellationToken = default);
    }
}
