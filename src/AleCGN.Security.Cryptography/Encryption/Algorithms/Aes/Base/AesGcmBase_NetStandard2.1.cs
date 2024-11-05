#if NETSTANDARD2_1

using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
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
        internal readonly IEncoder _encoder;
        private AesGcm _aesGcm;
        private byte[] _key;

        #endregion Fields


        #region Constructors/destructors

        public AesGcmBase(IEncoder encoder)
        {
            _encoder = encoder;
        }
        
        public AesGcmBase(IEncoder encoder, byte[] key)
        {
            _encoder = encoder;
            _key = key;
            _aesGcm = new AesGcm(_key);
        }

        public AesGcmBase(IEncoder encoder, string encodedKey)
        {
            _encoder = encoder;
            _key = _encoder.Decode(encodedKey);
            _aesGcm = new AesGcm(_key);
        }

        ~AesGcmBase()
        {
            _aesGcm?.Dispose();
        }

        #endregion Constructors/destructors


        #region Public methods

        #region Encryption

        public byte[] EncryptData(byte[] data)
        {
            CheckInputData(data, nameof(data));

            var nonce = GenerateNonce();
            var tag = new byte[_tagSize];
            var encryptedData = new byte[data.Length];

            EncryptDataInternal(data, tag, nonce, encryptedData);

            var encryptedDataWithMetadata = GetEncryptedDataWithMetadata(encryptedData, tag, nonce);

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

            var (encryptedData, tag, nonce) = GetMetadataFromEncryptedData(encryptedDataWithMetadata);
            var decryptedData = new byte[encryptedData.Length];

            DecryptDataInternal(encryptedData, tag, nonce, decryptedData);

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

            CreateNewAesGcmInstance();
        }

        public void SetOrUpdateKey(string encodedKey)
        {
            _key = _encoder.Decode(encodedKey);

            CreateNewAesGcmInstance();
        }

        #endregion Key set/update


        #endregion Public methods


        #region Private methods

        private void CheckInputData(byte[] inputData, string paramName)
        {
            if (inputData == null || inputData.Length <= 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, paramName);
            }
        }

        private byte[] GenerateNonce()
            => CryptographyHelper.GenerateSecureRandomBytes(_nonceSize);

        private void EncryptDataInternal(byte[] data, byte[] tag, byte[] nonce, byte[] encryptedData)
        {
            if (_key == null || _key.Length == 0)
            {
                throw new CryptographicException(LibraryResources.Validation_AESKeyNotSet);
            }

            _aesGcm.Encrypt(
                nonce,
                data,
                encryptedData,
                tag
            );
        }

        private byte[] GetEncryptedDataWithMetadata(
            byte[] encryptedData,
            byte[] tag,
            byte[] nonce)
        {
            var encryptedDataWithMetadataSize = GetEncryptedDataWithMetadataSize(encryptedData.Length);
            var encryptedDataWithMetada = new byte[encryptedDataWithMetadataSize];

            Array.Copy(
                encryptedData,
                0,
                encryptedDataWithMetada,
                0,
                encryptedData.Length
            );

            Array.Copy(
                tag,
                0,
                encryptedDataWithMetada,
                encryptedData.Length,
                _tagSize
            );

            Array.Copy(
                nonce,
                0,
                encryptedDataWithMetada,
                encryptedData.Length + _tagSize,
                _nonceSize
            );

            return encryptedDataWithMetada;
        }

        private int GetEncryptedDataWithMetadataSize(int encryptedDataSize)
            => encryptedDataSize + _tagSize + _nonceSize;

        private void CheckInputText(string inputText, string paramName)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, paramName);
            }
        }

        private (byte[] EncryptedData, byte[] Tag, byte[] Nonce) GetMetadataFromEncryptedData(byte[] encrypteDataWithMetada)
        {
            ValidateEncryptedDataWithMetadataSize(encrypteDataWithMetada);

            var encryptedData = new byte[encrypteDataWithMetada.Length - _nonceSize - _tagSize];

            Array.Copy(
                encrypteDataWithMetada,
                0,
                encryptedData,
                0,
                encryptedData.Length
            );

            var tag = new byte[_tagSize];

            Array.Copy(
                encrypteDataWithMetada,
                encryptedData.Length,
                tag,
                0,
                _tagSize
            );

            var nonce = new byte[_nonceSize];

            Array.Copy(
                encrypteDataWithMetada,
                encryptedData.Length + _tagSize,
                nonce,
                0,
                _nonceSize
            );

            return (EncryptedData: encryptedData, Tag: tag, Nonce: nonce);
        }

        private void ValidateEncryptedDataWithMetadataSize(byte[] encryptedDataWithMetada)
        {
            if (encryptedDataWithMetada is null ||
                encryptedDataWithMetada.Length < _nonceSize + _tagSize + _encryptedDataMinimumSize)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_EncryptedDataSize, nameof(encryptedDataWithMetada));
            }
        }

        private void DecryptDataInternal(byte[] encryptedDataToDecrypt, byte[] tag, byte[] nonce, byte[] decryptedData)
        {
            if (_key == null || _key.Length == 0)
            {
                throw new CryptographicException(LibraryResources.Validation_AESKeyNotSet);
            }

            _aesGcm.Decrypt(
                nonce,
                encryptedDataToDecrypt,
                tag,
                decryptedData
            );
        }

        private void CreateNewAesGcmInstance()
        {
            _aesGcm?.Dispose();
            _aesGcm = null;
            _aesGcm = new AesGcm(_key);
        }

        #endregion Private methods
    }
}

#endif