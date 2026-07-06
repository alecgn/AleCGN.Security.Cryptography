#if !NETSTANDARD2_0

using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes.Helpers;
using AleCGN.Security.Cryptography.Resources;
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
        private const int _encryptedDataMinimumSize = 1;
        private readonly IEncoder _encoder;
        private readonly AesKeySizes _aesKeySize;
        private AesGcm _aesGcm;
        private byte[] _key;
        private bool _disposed;

        #endregion Fields


        #region Constructors

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;
        }

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder, byte[] key)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;

            SetOrUpdateKey(key);
        }

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder, string encodedKey)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;

            SetOrUpdateKey(encodedKey);
        }

        #endregion Constructors


        #region Public methods

        #region Encryption

        public byte[] EncryptData(byte[] data)
        {
            CheckInputData(data, nameof(data));
            CheckKeySet();

            // Output layout: ciphertext || tag || nonce. Encrypting directly into
            // slices of the final buffer avoids intermediate arrays and copies.
            var encryptedDataWithMetadata = new byte[data.Length + _tagSize + _nonceSize];
            var ciphertext = encryptedDataWithMetadata.AsSpan(0, data.Length);
            var tag = encryptedDataWithMetadata.AsSpan(data.Length, _tagSize);
            var nonce = encryptedDataWithMetadata.AsSpan(data.Length + _tagSize, _nonceSize);

            RandomNumberGenerator.Fill(nonce);

            _aesGcm.Encrypt(nonce, data, ciphertext, tag);

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

            var ciphertextLength = encryptedDataWithMetadata.Length - _tagSize - _nonceSize;
            var ciphertext = encryptedDataWithMetadata.AsSpan(0, ciphertextLength);
            var tag = encryptedDataWithMetadata.AsSpan(ciphertextLength, _tagSize);
            var nonce = encryptedDataWithMetadata.AsSpan(ciphertextLength + _tagSize, _nonceSize);
            var decryptedData = new byte[ciphertextLength];

            _aesGcm.Decrypt(nonce, ciphertext, tag, decryptedData);

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

            _aesGcm?.Dispose();
            _aesGcm = null;

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

        private void ReplaceKey(byte[] newKey)
        {
            _aesGcm?.Dispose();

            ClearKey();

            _key = newKey;
#if NET8_0_OR_GREATER
            _aesGcm = new AesGcm(_key, _tagSize);
#else
            _aesGcm = new AesGcm(_key);
#endif
        }

        private void ClearKey()
        {
            if (_key != null)
            {
                CryptographicOperations.ZeroMemory(_key);

                _key = null;
            }
        }

        #endregion Private methods
    }
}

#endif
