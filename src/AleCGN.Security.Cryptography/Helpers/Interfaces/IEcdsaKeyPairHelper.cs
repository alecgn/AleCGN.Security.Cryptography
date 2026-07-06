namespace AleCGN.Security.Cryptography
{
    public interface IEcdsaKeyPairHelper
    {
        AsymmetricKeyPair GenerateKeyPair(EcdsaCurves curve = EcdsaCurves.NistP256);
    }
}
