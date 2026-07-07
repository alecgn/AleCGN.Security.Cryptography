using AleCGN.Security.Cryptography.Constants;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
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
        private const int _fieldCount = 3; // nonce | tag | ciphertext
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
            var ciphertextWithTagSize = cipher.GetOutputSize(data.Length);
            var ciphertextWithTag = new byte[ciphertextWithTagSize];

            var length = cipher.ProcessBytes(data, 0, data.Length, ciphertextWithTag, 0);

            cipher.DoFinal(ciphertextWithTag, length);

            // Self-describing envelope with explicit fields: nonce | tag | ciphertext.
            var ciphertextSize = ciphertextWithTagSize - _tagSize;
            var payload = PayloadFormat.CreateBinary(
                PayloadAlgorithms.ChaCha20Poly1305,
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
            var fields = PayloadFormat.ParseBinary(payload, PayloadAlgorithms.ChaCha20Poly1305, _fieldCount, nameof(text));

            return PayloadFormat.BuildString(
                PayloadAlgorithms.ChaCha20Poly1305Name, null, PayloadFormat.GetFields(payload, fields));
        }

        public byte[] DecryptData(byte[] encryptedDataWithMetadata)
            => DecryptData(encryptedDataWithMetadata, null);

        public byte[] DecryptData(byte[] encryptedDataWithMetadata, byte[] associatedData)
        {
            CheckInputData(encryptedDataWithMetadata, nameof(encryptedDataWithMetadata));
            CheckKeySet();

            var fields = PayloadFormat.ParseBinary(
                encryptedDataWithMetadata, PayloadAlgorithms.ChaCha20Poly1305, _fieldCount, nameof(encryptedDataWithMetadata));

            if (fields[0].Length != _nonceSize || fields[1].Length != _tagSize || fields[2].Length == 0)
            {
                throw PayloadFormat.CreateInvalidPayloadException(nameof(encryptedDataWithMetadata));
            }

            var nonce = PayloadFormat.GetField(encryptedDataWithMetadata, fields[0]);

            // BouncyCastle consumes ciphertext||tag contiguously.
            var ciphertextWithTag = new byte[fields[2].Length + _tagSize];

            Array.Copy(encryptedDataWithMetadata, fields[2].Offset, ciphertextWithTag, 0, fields[2].Length);
            Array.Copy(encryptedDataWithMetadata, fields[1].Offset, ciphertextWithTag, fields[2].Length, _tagSize);

            var cipher = CreateCipher(forEncryption: false, nonce, associatedData);
            var decryptedData = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];

            var length = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, decryptedData, 0);

            cipher.DoFinal(decryptedData, length);

            return decryptedData;
        }

        public string DecryptText(string encryptedTextWithMetadata)
            => DecryptText(encryptedTextWithMetadata, null);

        public string DecryptText(string encryptedTextWithMetadata, byte[] associatedData)
        {
            CheckInputText(encryptedTextWithMetadata, nameof(encryptedTextWithMetadata));

            var (_, fields) = PayloadFormat.ParseString(
                encryptedTextWithMetadata, PayloadAlgorithms.ChaCha20Poly1305Name, _fieldCount,
                hasParameters: false, nameof(encryptedTextWithMetadata));

            var payload = PayloadFormat.BuildBinary(PayloadAlgorithms.ChaCha20Poly1305, fields);

            return DecryptData(payload, associatedData).ToUTF8String();
        }

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
