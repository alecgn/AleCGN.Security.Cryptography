using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Encryption.PasswordBased
{
    public interface IPasswordBasedEncryption
    {
        byte[] EncryptData(byte[] data, string password);

        string EncryptText(string text, string password);

        byte[] DecryptData(byte[] encryptedDataWithMetadata, string password);

        string DecryptText(string encryptedTextWithMetadata, string password);

        Task<byte[]> EncryptDataAsync(byte[] data, string password, CancellationToken cancellationToken = default);

        Task<string> EncryptTextAsync(string text, string password, CancellationToken cancellationToken = default);

        Task<byte[]> DecryptDataAsync(byte[] encryptedDataWithMetadata, string password, CancellationToken cancellationToken = default);

        Task<string> DecryptTextAsync(string encryptedTextWithMetadata, string password, CancellationToken cancellationToken = default);
    }
}
