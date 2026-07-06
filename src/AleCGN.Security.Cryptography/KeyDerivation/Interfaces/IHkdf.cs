using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    public interface IHkdf
    {
        byte[] DeriveKey(byte[] inputKeyMaterial, int derivedKeySize, byte[] salt = null, byte[] info = null);

        string DeriveTextKey(string inputKeyMaterial, int derivedKeySize, string salt = null, string info = null);

        Task<byte[]> DeriveKeyAsync(
            byte[] inputKeyMaterial,
            int derivedKeySize,
            byte[] salt = null,
            byte[] info = null,
            CancellationToken cancellationToken = default);

        Task<string> DeriveTextKeyAsync(
            string inputKeyMaterial,
            int derivedKeySize,
            string salt = null,
            string info = null,
            CancellationToken cancellationToken = default);
    }
}
