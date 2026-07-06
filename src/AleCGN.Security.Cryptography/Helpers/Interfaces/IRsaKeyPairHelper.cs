namespace AleCGN.Security.Cryptography
{
    public interface IRsaKeyPairHelper
    {
        AsymmetricKeyPair GenerateKeyPair(RsaKeySizes keySize = RsaKeySizes.KeySize2048Bits);
    }
}
