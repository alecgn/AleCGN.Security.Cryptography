using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public class AesGcm256 : AesGcmBase, IAesGcm256
    {
        private const AesKeySizes _aesKeySize = AesKeySizes.KeySize256Bits;


        public AesGcm256(IEncoder encoder) : base(_aesKeySize, encoder) { }

        public AesGcm256(IEncoder encoder, byte[] key) : base(_aesKeySize, encoder, key) { }

        public AesGcm256(IEncoder encoder, string encodedKey) : base(_aesKeySize, encoder, encodedKey) { }
    }
}