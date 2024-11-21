using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public class AesGcm192 : AesGcmBase, IAesGcm192
    {
        private const AesKeySizes _aesKeySize = AesKeySizes.KeySize192Bits;


        public AesGcm192(IEncoder encoder) : base(_aesKeySize, encoder) { }

        public AesGcm192(IEncoder encoder, byte[] key) : base(_aesKeySize, encoder, key) { }

        public AesGcm192(IEncoder encoder, string encodedKey) : base(_aesKeySize, encoder, encodedKey) { }
    }
}