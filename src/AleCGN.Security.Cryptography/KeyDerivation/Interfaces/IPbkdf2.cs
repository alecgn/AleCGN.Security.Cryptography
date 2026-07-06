using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    public interface IPbkdf2
    {
        byte[] DeriveKey(byte[] password, out byte[] salt);

        byte[] DeriveKey(byte[] password, byte[] salt);

        string DeriveTextKey(string password, out string encodedSalt);

        string DeriveTextKey(string password, string encodedSalt);

        Task<KeyDerivationResult> DeriveKeyAsync(byte[] password, CancellationToken cancellationToken = default);

        Task<byte[]> DeriveKeyAsync(byte[] password, byte[] salt, CancellationToken cancellationToken = default);

        Task<EncodedKeyDerivationResult> DeriveTextKeyAsync(string password, CancellationToken cancellationToken = default);

        Task<string> DeriveTextKeyAsync(string password, string encodedSalt, CancellationToken cancellationToken = default);

        bool VerifyKey(byte[] password, byte[] salt, byte[] expectedDerivedKey);

        bool VerifyTextKey(string password, string encodedSalt, string encodedExpectedDerivedKey);

        Task<bool> VerifyKeyAsync(byte[] password, byte[] salt, byte[] expectedDerivedKey, CancellationToken cancellationToken = default);

        Task<bool> VerifyTextKeyAsync(string password, string encodedSalt, string encodedExpectedDerivedKey, CancellationToken cancellationToken = default);
    }
}
