using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography
{
    public interface IRsaKeyPairHelper
    {
        AsymmetricKeyPair GenerateKeyPair(RsaKeySizes keySize = RsaKeySizes.KeySize2048Bits);

        Task<AsymmetricKeyPair> GenerateKeyPairAsync(
            RsaKeySizes keySize = RsaKeySizes.KeySize2048Bits,
            CancellationToken cancellationToken = default);
    }
}
