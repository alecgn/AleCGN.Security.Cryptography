using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography
{
    public interface IEcdsaKeyPairHelper
    {
        AsymmetricKeyPair GenerateKeyPair(EcdsaCurves curve = EcdsaCurves.NistP256);

        Task<AsymmetricKeyPair> GenerateKeyPairAsync(
            EcdsaCurves curve = EcdsaCurves.NistP256,
            CancellationToken cancellationToken = default);
    }
}
