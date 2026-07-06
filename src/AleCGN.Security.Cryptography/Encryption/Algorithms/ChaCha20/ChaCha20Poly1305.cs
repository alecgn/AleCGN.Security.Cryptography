using AleCGN.Security.Cryptography.Constants;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20
{
    /// <summary>
    /// ChaCha20-Poly1305 (RFC 8439) authenticated encryption with a 256-bit key.
    /// A good alternative to AES-GCM on hardware without AES acceleration.
    /// Output layout: ciphertext || tag || nonce (same convention used by the AES-GCM classes).
    /// </summary>
    public class ChaCha20Poly1305 : IChaCha20Poly1305
    {
        #region Fields

        private const int _keySize = 32;
        private const int _nonceSize = 12;
        private const int _tagSize = 16;
        private const int _tagBitsSize = _tagSize * ConstantValues.BitsPerByte;
        private const int _encryptedDataMinimumSize = 1;
        private readonly IEncoder _encoder;
        private byte[] _key;
        private bool _disposed;

        #endregion Fields


        #region Constructors

        public ChaCha20Poly1305(IEncoder encoder)
        {
            _encoder = encoder;
        }

        public ChaCha20Poly1305(IEncoder encoder, byte[] key) : this(encoder)
        {
            SetOrUpdateKey(key);
        }

        public ChaCha20Poly1305(IEncoder encoder, string encodedKey) : this(encoder)
        {
            SetOrUpdateKey(encodedKey);
        }

        #endregion Constructors


        #region Public methods

        public byte[] EncryptData(byte[] data)
            => EncryptData(data, null);

        public byte[] EncryptData(byte[] data, byte[] associatedData)
        {
            CheckInputData(data, nameof(data));
            CheckKeySet();

            var nonce = CryptographyHelper.GenerateSecureRandomBytes(_nonceSize);
            var cipher = CreateCipher(forEncryption: true, nonce, associatedData);
            var encryptedDataWithTagSize = cipher.GetOutputSize(data.Length);
            var encryptedDataWithMetadata = new byte[encryptedDataWithTagSize + _nonceSize];

            var length = cipher.ProcessBytes(data, 0, data.Length, encryptedDataWithMetadata, 0);

            cipher.DoFinal(encryptedDataWithMetadata, length);

            Array.Copy(nonce, 0, encryptedDataWithMetadata, encryptedDataWithTagSize, _nonceSize);

            return encryptedDataWithMetadata;
        }

        public string EncryptText(string text)
            => EncryptText(text, null);

        public string EncryptText(string text, byte[] associatedData)
        {
            CheckInputText(text, nameof(text));

            var textBytes = text.ToUTF8Bytes();
            var encryptedTextBytesWithMetadata = EncryptData(textBytes, associatedData);

            return _encoder.Encode(encryptedTextBytesWithMetadata);
        }

        public byte[] DecryptData(byte[] encryptedDataWithMetadata)
            => DecryptData(encryptedDataWithMetadata, null);

        public byte[] DecryptData(byte[] encryptedDataWithMetadata, byte[] associatedData)
        {
            CheckInputData(encryptedDataWithMetadata, nameof(encryptedDataWithMetadata));
            ValidateEncryptedDataWithMetadataSize(encryptedDataWithMetadata);
            CheckKeySet();

            var encryptedDataWithTagSize = encryptedDataWithMetadata.Length - _nonceSize;
            var nonce = new byte[_nonceSize];

            Array.Copy(encryptedDataWithMetadata, encryptedDataWithTagSize, nonce, 0, _nonceSize);

            var cipher = CreateCipher(forEncryption: false, nonce, associatedData);
            var decryptedData = new byte[cipher.GetOutputSize(encryptedDataWithTagSize)];

            var length = cipher.ProcessBytes(encryptedDataWithMetadata, 0, encryptedDataWithTagSize, decryptedData, 0);

            cipher.DoFinal(decryptedData, length);

            return decryptedData;
        }

        public string DecryptText(string encryptedTextWithMetadata)
            => DecryptText(encryptedTextWithMetadata, null);

        public string DecryptText(string encryptedTextWithMetadata, byte[] associatedData)
        {
            CheckInputText(encryptedTextWithMetadata, nameof(encryptedTextWithMetadata));

            var encryptedDataWithMetadata = _encoder.Decode(encryptedTextWithMetadata);
            var decryptedData = DecryptData(encryptedDataWithMetadata, associatedData);
            var decryptedText = decryptedData.ToUTF8String();

            return decryptedText;
        }

        public void SetOrUpdateKey(byte[] key)
        {
            if (key is null || key.Length != _keySize)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidKey, nameof(key));
            }

            // Defensive copy: mutations to the caller's array must not affect the key in use.
            var newKey = (byte[])key.Clone();

            ClearKey();

            _key = newKey;
        }

        public void SetOrUpdateKey(string encodedKey)
        {
            if (string.IsNullOrWhiteSpace(encodedKey))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encodedKey));
            }

            var newKey = _encoder.Decode(encodedKey);

            if (newKey.Length != _keySize)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidKey, nameof(encodedKey));
            }

            ClearKey();

            _key = newKey;
        }

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

        private Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 CreateCipher(bool forEncryption, byte[] nonce, byte[] associatedData)
        {
            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var aeadParameters = new AeadParameters(new KeyParameter(_key), _tagBitsSize, nonce, associatedData);

            cipher.Init(forEncryption, aeadParameters);

            return cipher;
        }

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
                throw new CryptographicException(LibraryResources.Validation_KeyNotSet);
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
