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
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public abstract class AesGcmBase : IAesGcmBase
    {
        #region Fields

        private const int _nonceSize = 12;
        private const int _tagSize = 16;
        private const int _tagBitsSize = _tagSize * ConstantValues.BitsPerByte;
        private const int _fieldCount = 3; // nonce | tag | ciphertext
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
            => EncryptData(data, null);

        public byte[] EncryptData(byte[] data, byte[] associatedData)
        {
            CheckInputData(data, nameof(data));
            CheckKeySet();

            var nonce = CryptographyHelper.GenerateSecureRandomBytes(_nonceSize);
            var ciphertextWithTagSize = InitCipherAndGetOutputSize(forEncryption: true, nonce, associatedData, data.Length);
            var ciphertextWithTag = new byte[ciphertextWithTagSize];

            var length = _gcmBlockCipher.ProcessBytes(data, 0, data.Length, ciphertextWithTag, 0);

            _gcmBlockCipher.DoFinal(ciphertextWithTag, length);

            // Self-describing envelope with explicit fields: nonce | tag | ciphertext.
            // BouncyCastle emits ciphertext||tag contiguously, so the two fields are split here.
            var ciphertextSize = ciphertextWithTagSize - _tagSize;
            var payload = PayloadFormat.CreateBinary(
                GetAlgorithmId(),
                new[] { _nonceSize, _tagSize, ciphertextSize },
                out var fieldOffsets);

            Array.Copy(nonce, 0, payload, fieldOffsets[0], _nonceSize);
            Array.Copy(ciphertextWithTag, ciphertextSize, payload, fieldOffsets[1], _tagSize);
            Array.Copy(ciphertextWithTag, 0, payload, fieldOffsets[2], ciphertextSize);

            return payload;
        }

        public string EncryptText(string text)
            => EncryptText(text, null);

        public string EncryptText(string text, byte[] associatedData)
        {
            CheckInputText(text, nameof(text));

            var payload = EncryptData(text.ToUTF8Bytes(), associatedData);
            var fields = PayloadFormat.ParseBinary(payload, GetAlgorithmId(), _fieldCount, nameof(text));

            return PayloadFormat.BuildString(GetAlgorithmName(), null, PayloadFormat.GetFields(payload, fields));
        }

        #endregion Encryption


        #region Decryption

        public byte[] DecryptData(byte[] encryptedDataWithMetadata)
            => DecryptData(encryptedDataWithMetadata, null);

        public byte[] DecryptData(byte[] encryptedDataWithMetadata, byte[] associatedData)
        {
            CheckInputData(encryptedDataWithMetadata, nameof(encryptedDataWithMetadata));
            CheckKeySet();

            var fields = PayloadFormat.ParseBinary(
                encryptedDataWithMetadata, GetAlgorithmId(), _fieldCount, nameof(encryptedDataWithMetadata));

            if (fields[0].Length != _nonceSize || fields[1].Length != _tagSize || fields[2].Length == 0)
            {
                throw PayloadFormat.CreateInvalidPayloadException(nameof(encryptedDataWithMetadata));
            }

            var nonce = PayloadFormat.GetField(encryptedDataWithMetadata, fields[0]);

            // BouncyCastle consumes ciphertext||tag contiguously.
            var ciphertextWithTag = new byte[fields[2].Length + _tagSize];

            Array.Copy(encryptedDataWithMetadata, fields[2].Offset, ciphertextWithTag, 0, fields[2].Length);
            Array.Copy(encryptedDataWithMetadata, fields[1].Offset, ciphertextWithTag, fields[2].Length, _tagSize);

            var decryptedDataSize = InitCipherAndGetOutputSize(forEncryption: false, nonce, associatedData, ciphertextWithTag.Length);
            var decryptedData = new byte[decryptedDataSize];

            var length = _gcmBlockCipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, decryptedData, 0);

            _gcmBlockCipher.DoFinal(decryptedData, length);

            return decryptedData;
        }

        public string DecryptText(string encryptedTextWithMetadata)
            => DecryptText(encryptedTextWithMetadata, null);

        public string DecryptText(string encryptedTextWithMetadata, byte[] associatedData)
        {
            CheckInputText(encryptedTextWithMetadata, nameof(encryptedTextWithMetadata));

            var (_, fields) = PayloadFormat.ParseString(
                encryptedTextWithMetadata, GetAlgorithmName(), _fieldCount, hasParameters: false, nameof(encryptedTextWithMetadata));

            var payload = PayloadFormat.BuildBinary(GetAlgorithmId(), fields);

            return DecryptData(payload, associatedData).ToUTF8String();
        }

        #endregion Decryption


        #region Async

        public Task<byte[]> EncryptDataAsync(byte[] data, CancellationToken cancellationToken = default)
            => EncryptDataAsync(data, null, cancellationToken);

        public Task<byte[]> EncryptDataAsync(byte[] data, byte[] associatedData, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptData(data, associatedData), cancellationToken);

        public Task<string> EncryptTextAsync(string text, CancellationToken cancellationToken = default)
            => EncryptTextAsync(text, null, cancellationToken);

        public Task<string> EncryptTextAsync(string text, byte[] associatedData, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptText(text, associatedData), cancellationToken);

        public Task<byte[]> DecryptDataAsync(byte[] encryptedDataWithMetadata, CancellationToken cancellationToken = default)
            => DecryptDataAsync(encryptedDataWithMetadata, null, cancellationToken);

        public Task<byte[]> DecryptDataAsync(byte[] encryptedDataWithMetadata, byte[] associatedData, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptData(encryptedDataWithMetadata, associatedData), cancellationToken);

        public Task<string> DecryptTextAsync(string encryptedTextWithMetadata, CancellationToken cancellationToken = default)
            => DecryptTextAsync(encryptedTextWithMetadata, null, cancellationToken);

        public Task<string> DecryptTextAsync(string encryptedTextWithMetadata, byte[] associatedData, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptText(encryptedTextWithMetadata, associatedData), cancellationToken);

        #endregion Async


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

        private byte GetAlgorithmId()
        {
            switch (_aesKeySize)
            {
                case AesKeySizes.KeySize128Bits:
                    return PayloadAlgorithms.Aes128Gcm;
                case AesKeySizes.KeySize192Bits:
                    return PayloadAlgorithms.Aes192Gcm;
                default:
                    return PayloadAlgorithms.Aes256Gcm;
            }
        }

        private string GetAlgorithmName()
        {
            switch (_aesKeySize)
            {
                case AesKeySizes.KeySize128Bits:
                    return PayloadAlgorithms.Aes128GcmName;
                case AesKeySizes.KeySize192Bits:
                    return PayloadAlgorithms.Aes192GcmName;
                default:
                    return PayloadAlgorithms.Aes256GcmName;
            }
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
                throw new CryptographicException(LibraryResources.Validation_AESKeyNotSet);
            }
        }

        private int InitCipherAndGetOutputSize(bool forEncryption, byte[] nonce, byte[] associatedData, int inputSize)
        {
            var aeadParameters = new AeadParameters(new KeyParameter(_key), _tagBitsSize, nonce, associatedData);

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
