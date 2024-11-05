using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public class AesGcm128 : AesGcmBase, IAesGcm128
    {
        private const AesKeySizes _aesKeySize = AesKeySizes.KeySize128Bits;

        
        public AesGcm128(IEncoder encoder) : base(encoder) { }

        public AesGcm128(IEncoder encoder, byte[] key) : base(encoder, ValidateAESKey(key).Invoke()) { }

        public AesGcm128(IEncoder encoder, string encodedKey) : base(encoder, ValidateAESKey(encoder.Decode(encodedKey)).Invoke()) { }

        public new void SetOrUpdateKey(byte[] key)
        {
            if (key == null || key.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(key));
            }

            AesHelper.ValidateAESKey(key, _aesKeySize);
            
            base.SetOrUpdateKey(key);
        }

        public new void SetOrUpdateKey(string encodedKey)
        {
            if (string.IsNullOrWhiteSpace(encodedKey))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encodedKey));
            }

            var key = _encoder.Decode(encodedKey);
            
            AesHelper.ValidateAESKey(key, _aesKeySize);
            base.SetOrUpdateKey(key);
        }

        private static Func<byte[]> ValidateAESKey(byte[] key)
        {
            byte[] funcValidateAESKey()
            {
                AesHelper.ValidateAESKey(key, _aesKeySize);

                return key;
            }

            return funcValidateAESKey;
        }
    }
}