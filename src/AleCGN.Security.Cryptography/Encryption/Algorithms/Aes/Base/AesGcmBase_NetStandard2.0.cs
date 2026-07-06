#if NETSTANDARD2_0

using AleCGN.Security.Cryptography.Constants;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes.Helpers;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public abstract class AesGcmBase : IAesGcmBase
    {
        #region Fields

        private const int _nonceSize = 12;
        private const int _tagSize = 16;
        private const int _tagBitsSize = _tagSize * ConstantValues.BitsPerByte;
        private const int _encryptedDataMinimumSize = 1;
        private readonly IEncoder _encoder;
        private readonly AesKeySizes _aesKeySize;
        private readonly GcmBlockCipher _gcmBlockCipher;
        private byte[] _key;
        private bool _disposed;

        #endregion Fields


        #region Constructors

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;
            _gcmBlockCipher = new GcmBlockCipher(new AesEngine());
        }

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder, byte[] key)
            : this(aesKeySize, encoder)
        {
            SetOrUpdateKey(key);
        }

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder, string encodedKey)
            : this(aesKeySize, encoder)
        {
            SetOrUpdateKey(encodedKey);
        }

        #endregion Constructors


        #region Public methods

        #region Encryption

        public byte[] EncryptData(byte[] data)
        {
            CheckInputData(data, nameof(data));
            CheckKeySet();

            // Output layout: ciphertext || tag || nonce. BouncyCastle already emits
            // ciphertext and tag together, so it writes straight into the final buffer.
            var nonce = GenerateNonce();
            var encryptedDataWithTagSize = InitCipherAndGetOutputSize(forEncryption: true, nonce, data.Length);
            var encryptedDataWithMetadata = new byte[encryptedDataWithTagSize + _nonceSize];

            var length = _gcmBlockCipher.ProcessBytes(data, 0, data.Length, encryptedDataWithMetadata, 0);

            _gcmBlockCipher.DoFinal(encryptedDataWithMetadata, length);

            Array.Copy(nonce, 0, encryptedDataWithMetadata, encryptedDataWithTagSize, _nonceSize);

            return encryptedDataWithMetadata;
        }

        public string EncryptText(string text)
        {
            CheckInputText(text, nameof(text));

            var textBytes = text.ToUTF8Bytes();
            var encryptedTextBytesWithMetadata = EncryptData(textBytes);

            return _encoder.Encode(encryptedTextBytesWithMetadata);
        }

        #endregion Encryption


        #region Decryption

        public byte[] DecryptData(byte[] encryptedDataWithMetadata)
        {
            CheckInputData(encryptedDataWithMetadata, nameof(encryptedDataWithMetadata));
            ValidateEncryptedDataWithMetadataSize(encryptedDataWithMetadata);
            CheckKeySet();

            var encryptedDataWithTagSize = encryptedDataWithMetadata.Length - _nonceSize;
            var nonce = new byte[_nonceSize];

            Array.Copy(encryptedDataWithMetadata, encryptedDataWithTagSize, nonce, 0, _nonceSize);

            var decryptedDataSize = InitCipherAndGetOutputSize(forEncryption: false, nonce, encryptedDataWithTagSize);
            var decryptedData = new byte[decryptedDataSize];

            var length = _gcmBlockCipher.ProcessBytes(encryptedDataWithMetadata, 0, encryptedDataWithTagSize, decryptedData, 0);

            _gcmBlockCipher.DoFinal(decryptedData, length);

            return decryptedData;
        }

        public string DecryptText(string encryptedTextWithMetadata)
        {
            CheckInputText(encryptedTextWithMetadata, nameof(encryptedTextWithMetadata));

            var encryptedDataWithMetadata = _encoder.Decode(encryptedTextWithMetadata);
            var decryptedData = DecryptData(encryptedDataWithMetadata);
            var decryptedText = decryptedData.ToUTF8String();

            return decryptedText;
        }

        #endregion Decryption


        #region Key set/update

        public void SetOrUpdateKey(byte[] key)
        {
            AesHelper.ValidateAESKey(key, _aesKeySize);

            // Defensive copy: mutations to the caller's array must not affect the key in use.
            var newKey = (byte[])key.Clone();

            ReplaceKey(newKey);
        }

        public void SetOrUpdateKey(string encodedKey)
        {
            var newKey = _encoder.Decode(encodedKey);

            AesHelper.ValidateAESKey(newKey, _aesKeySize);

            ReplaceKey(newKey);
        }

        #endregion Key set/update


        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            ClearKey();

            _disposed = true;
        }

        #endregion Public methods


        #region Private methods

        private void CheckInputData(byte[] inputData, string paramName)
        {
            if (inputData == null || inputData.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, paramName);
            }
        }

        private void CheckInputText(string inputText, string paramName)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, paramName);
            }
        }

        private void CheckKeySet()
        {
            if (_key == null || _key.Length == 0)
            {
                throw new CryptographicException(LibraryResources.Validation_AESKeyNotSet);
            }
        }

        private void ValidateEncryptedDataWithMetadataSize(byte[] encryptedDataWithMetadata)
        {
            if (encryptedDataWithMetadata is null ||
                encryptedDataWithMetadata.Length < _nonceSize + _tagSize + _encryptedDataMinimumSize)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_EncryptedDataSize, nameof(encryptedDataWithMetadata));
            }
        }

        private byte[] GenerateNonce()
            => CryptographyHelper.GenerateSecureRandomBytes(_nonceSize);

        private int InitCipherAndGetOutputSize(bool forEncryption, byte[] nonce, int inputSize)
        {
            var aeadParameters = new AeadParameters(new KeyParameter(_key), _tagBitsSize, nonce, null);

            _gcmBlockCipher.Init(forEncryption, aeadParameters);

            return _gcmBlockCipher.GetOutputSize(inputSize);
        }

        private void ReplaceKey(byte[] newKey)
        {
            ClearKey();

            _key = newKey;
        }

        private void ClearKey()
        {
            if (_key != null)
            {
                Array.Clear(_key, 0, _key.Length);

                _key = null;
            }
        }

        #endregion Private methods
    }
}

#endif
