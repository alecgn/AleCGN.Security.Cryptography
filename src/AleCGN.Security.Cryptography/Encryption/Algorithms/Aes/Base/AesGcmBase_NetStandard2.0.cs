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

        #endregion Fields


        #region Constructors

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;
            _gcmBlockCipher = new GcmBlockCipher(new AesEngine());
        }

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder, byte[] key)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;
            _key = key;
            _gcmBlockCipher = new GcmBlockCipher(new AesEngine());

            ValidateAESKey();
        }

        public AesGcmBase(AesKeySizes aesKeySize, IEncoder encoder, string encodedKey)
        {
            _aesKeySize = aesKeySize;
            _encoder = encoder;
            _key = _encoder.Decode(encodedKey);
            _gcmBlockCipher = new GcmBlockCipher(new AesEngine());

            ValidateAESKey();
        }

        #endregion Constructors


        #region Public methods


        #region Encryption

        public byte[] EncryptData(byte[] data)
        {
            CheckInputData(data, nameof(data));

            var nonce = GenerateNonce();
            var encryptedDataWithTag = EncryptDataInternal(data, nonce);
            var encryptedDataWithMetadata = GetEncryptedDataWithMetadata(encryptedDataWithTag, nonce);

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

            var (encryptedDataWithTag, nonce) = GetMetadataFromEncryptedData(encryptedDataWithMetadata);
            var decryptedData = DecryptDataInternal(encryptedDataWithTag, nonce);

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
            _key = key;

            ValidateAESKey();
        }

        public void SetOrUpdateKey(string encodedKey)
        {
            _key = _encoder.Decode(encodedKey);

            ValidateAESKey();
        }

        #endregion Key set/update


        #endregion Public methods


        #region Private methods

        private void ValidateAESKey()
            => AesHelper.ValidateAESKey(_key, _aesKeySize);

        private void CheckInputData(byte[] inputData, string paramName)
        {
            if (inputData == null || inputData.Length <= 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, paramName);
            }
        }

        private byte[] GenerateNonce()
            => CryptographyHelper.GenerateSecureRandomBytes(_nonceSize);

        private byte[] EncryptDataInternal(byte[] data, byte[] nonce)
        {
            if (_key == null || _key.Length == 0)
            {
                throw new CryptographicException(LibraryResources.Validation_AESKeyNotSet);
            }

            var aeadParameters = new AeadParameters(new KeyParameter(_key), _tagBitsSize, nonce, null);

            _gcmBlockCipher.Init(true, aeadParameters);

            var encryptedDataWithTag = new byte[_gcmBlockCipher.GetOutputSize(data.Length)];
            var resultLength = _gcmBlockCipher.ProcessBytes(data, 0, data.Length, encryptedDataWithTag, 0);

            _gcmBlockCipher.DoFinal(encryptedDataWithTag, resultLength);

            return encryptedDataWithTag;
        }

        private byte[] GetEncryptedDataWithMetadata(
            byte[] encryptedDataWithTag,
            byte[] nonce)
        {
            var encryptedDataWithMetadataSize = GetEncryptedDataWithMetadataSize(encryptedDataWithTag.Length);
            var encryptedDataWithMetada = new byte[encryptedDataWithMetadataSize];

            Array.Copy(
                encryptedDataWithTag,
                0,
                encryptedDataWithMetada,
                0,
                encryptedDataWithTag.Length
            );

            Array.Copy(
                nonce,
                0,
                encryptedDataWithMetada,
                encryptedDataWithTag.Length,
                _nonceSize
            );

            return encryptedDataWithMetada;
        }

        private int GetEncryptedDataWithMetadataSize(int encryptedDataWithTagSize)
            => encryptedDataWithTagSize + _nonceSize;

        private void CheckInputText(string inputText, string paramName)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, paramName);
            }
        }

        private (byte[] EncryptedDataWithTag, byte[] Nonce) GetMetadataFromEncryptedData(byte[] encrypteDataWithMetada)
        {
            ValidateEncryptedDataWithMetadataSize(encrypteDataWithMetada);

            var encryptedDataWithTag = new byte[encrypteDataWithMetada.Length - _nonceSize];

            Array.Copy(
                encrypteDataWithMetada,
                0,
                encryptedDataWithTag,
                0,
                encryptedDataWithTag.Length
            );

            var nonce = new byte[_nonceSize];

            Array.Copy(
                encrypteDataWithMetada,
                encryptedDataWithTag.Length,
                nonce,
                0,
                _nonceSize
            );

            return (EncryptedDataWithTag: encryptedDataWithTag, Nonce: nonce);
        }

        private void ValidateEncryptedDataWithMetadataSize(byte[] encryptedDataWithMetada)
        {
            if (encryptedDataWithMetada is null ||
                encryptedDataWithMetada.Length < _nonceSize + _tagSize + _encryptedDataMinimumSize
            )
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_EncryptedDataSize, nameof(encryptedDataWithMetada));
            }
        }

        private byte[] DecryptDataInternal(byte[] encryptedDataWithTag, byte[] nonce)
        {
            if (_key == null || _key.Length == 0)
            {
                throw new CryptographicException(LibraryResources.Validation_AESKeyNotSet);
            }

            var aeadParameters = new AeadParameters(new KeyParameter(_key), _tagBitsSize, nonce, null);

            _gcmBlockCipher.Init(false, aeadParameters);

            var decryptedData = new byte[_gcmBlockCipher.GetOutputSize(encryptedDataWithTag.Length)];
            var retLen = _gcmBlockCipher.ProcessBytes(encryptedDataWithTag, 0, encryptedDataWithTag.Length, decryptedData, 0);

            _gcmBlockCipher.DoFinal(decryptedData, retLen);

            return decryptedData;
        }

        #endregion Private methods
    }
}

#endif