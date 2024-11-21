using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public class AesGcm128 : AesGcmBase, IAesGcm128
    {
        private const AesKeySizes _aesKeySize = AesKeySizes.KeySize128Bits;

        
        public AesGcm128(IEncoder encoder) : base(_aesKeySize, encoder) { }

        public AesGcm128(IEncoder encoder, byte[] key) : base(_aesKeySize, encoder, key) { }

        public AesGcm128(IEncoder encoder, string encodedKey) : base(_aesKeySize, encoder, encodedKey) { }
    }
}