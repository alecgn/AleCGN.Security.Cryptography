using AleCGN.Security.Cryptography.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace AleCGN.Security.Cryptography
{
    public class RsaKeyPairHelper : IRsaKeyPairHelper
    {
        public AsymmetricKeyPair GenerateKeyPair(RsaKeySizes keySize = RsaKeySizes.KeySize2048Bits)
        {
            var generator = new RsaKeyPairGenerator();

            generator.Init(new KeyGenerationParameters(new SecureRandom(), (int)keySize));

            var keyPair = generator.GenerateKeyPair();

            return new AsymmetricKeyPair(
                PemKeyHelper.WritePem(keyPair.Public),
                PemKeyHelper.WritePem(keyPair.Private)
            );
        }
    }
}
