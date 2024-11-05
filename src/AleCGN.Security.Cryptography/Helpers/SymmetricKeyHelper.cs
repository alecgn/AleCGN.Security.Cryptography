using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Helpers;

namespace AleCGN.Security.Cryptography
{
    public class SymmetricKeyHelper : ISymmetricKeyHelper
    {
        private readonly IEncoder _encoder;

        public SymmetricKeyHelper(IEncoder encoder)
        {
            _encoder = encoder;
        }

        public byte[] GenerateSecureRandom128BitKey()
            => CryptographyHelper.GenerateSecureRandomBytes(SymmetricKeySizes.KeySize128Bits.ToBytesSize());

        public string GenerateSecureRandom128BitEncodedKey()
        {
            var key = GenerateSecureRandom128BitKey();
            
            return _encoder.Encode(key);
        }

        public byte[] GenerateSecureRandom192BitKey()
            => CryptographyHelper.GenerateSecureRandomBytes(SymmetricKeySizes.KeySize192Bits.ToBytesSize());

        public string GenerateSecureRandom192BitEncodedKey()
        {
            var key = GenerateSecureRandom192BitKey();

            return _encoder.Encode(key);
        }

        public byte[] GenerateSecureRandom256BitKey()
            => CryptographyHelper.GenerateSecureRandomBytes(SymmetricKeySizes.KeySize256Bits.ToBytesSize());

        public string GenerateSecureRandom256BitEncodedKey()
        {
            var key = GenerateSecureRandom256BitKey();

            return _encoder.Encode(key);
        }
    }
}
