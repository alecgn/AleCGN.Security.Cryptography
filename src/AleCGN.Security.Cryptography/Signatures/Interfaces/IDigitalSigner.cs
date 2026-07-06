using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Signatures
{
    public interface IDigitalSigner
    {
        byte[] SignData(byte[] data);

        string SignText(string text);

        bool VerifySignature(byte[] data, byte[] signature);

        bool VerifyTextSignature(string text, string encodedSignature);

        Task<byte[]> SignDataAsync(byte[] data, CancellationToken cancellationToken = default);

        Task<string> SignTextAsync(string text, CancellationToken cancellationToken = default);

        Task<bool> VerifySignatureAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default);

        Task<bool> VerifyTextSignatureAsync(string text, string encodedSignature, CancellationToken cancellationToken = default);
    }
}
