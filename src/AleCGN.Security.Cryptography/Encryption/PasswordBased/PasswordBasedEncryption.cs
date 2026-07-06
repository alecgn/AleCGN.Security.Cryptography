using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.KeyDerivation;
using AleCGN.Security.Cryptography.Resources;
using System;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.PasswordBased
{
    /// <summary>
    /// Password-based encryption combining PBKDF2 key derivation with AES-GCM-256.
    /// The output payload is self-contained: a header with the KDF parameters and salt is prepended
    /// to the AES-GCM output, and is also used as associated data, so tampering with the parameters
    /// causes decryption to fail. Data encrypted with older configurations remains decryptable.
    /// </summary>
    public class PasswordBasedEncryption : IPasswordBasedEncryption
    {
        // Header layout: version (1) | PRF (1) | iterations (4, little-endian) | salt size (1) | salt.
        private const byte _formatVersion = 1;
        private const int _headerFixedSize = 7;
        private const int _derivedKeySize = 32;

        private readonly IEncoder _encoder;
        private readonly Pbkdf2Configuration _configuration;

        public PasswordBasedEncryption(IEncoder encoder) : this(encoder, Pbkdf2Configuration.Default) { }

        public PasswordBasedEncryption(IEncoder encoder, Pbkdf2Configuration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            // The salt size is stored in a single header byte.
            if (configuration.SaltSize > byte.MaxValue)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentOutOfRange, nameof(configuration));
            }

            _encoder = encoder;
            _configuration = configuration;
        }

        public byte[] EncryptData(byte[] data, string password)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            CheckPassword(password);

            var encryptionConfiguration = new Pbkdf2Configuration(
                _configuration.PseudoRandomFunction, _configuration.Iterations, _configuration.SaltSize, _derivedKeySize);
            var pbkdf2 = new Pbkdf2(_encoder, encryptionConfiguration);
            var derivedKey = pbkdf2.DeriveKey(password.ToUTF8Bytes(), out var salt);

            try
            {
                var header = BuildHeader(salt);

                using (var aesGcm256 = new AesGcm256(_encoder, derivedKey))
                {
                    var encryptedData = aesGcm256.EncryptData(data, associatedData: header);
                    var payload = new byte[header.Length + encryptedData.Length];

                    Array.Copy(header, 0, payload, 0, header.Length);
                    Array.Copy(encryptedData, 0, payload, header.Length, encryptedData.Length);

                    return payload;
                }
            }
            finally
            {
                Array.Clear(derivedKey, 0, derivedKey.Length);
            }
        }

        public string EncryptText(string text, string password)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            return _encoder.Encode(EncryptData(text.ToUTF8Bytes(), password));
        }

        public byte[] DecryptData(byte[] encryptedDataWithMetadata, string password)
        {
            if (encryptedDataWithMetadata is null || encryptedDataWithMetadata.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(encryptedDataWithMetadata));
            }

            CheckPassword(password);

            var (pseudoRandomFunction, iterations, salt, headerSize) = ParseHeader(encryptedDataWithMetadata);

            var pbkdf2 = new Pbkdf2(_encoder, GetKeyDerivationConfiguration(pseudoRandomFunction, iterations));
            var derivedKey = pbkdf2.DeriveKey(password.ToUTF8Bytes(), salt);

            try
            {
                var header = new byte[headerSize];

                Array.Copy(encryptedDataWithMetadata, 0, header, 0, headerSize);

                var encryptedData = new byte[encryptedDataWithMetadata.Length - headerSize];

                Array.Copy(encryptedDataWithMetadata, headerSize, encryptedData, 0, encryptedData.Length);

                using (var aesGcm256 = new AesGcm256(_encoder, derivedKey))
                {
                    return aesGcm256.DecryptData(encryptedData, associatedData: header);
                }
            }
            finally
            {
                Array.Clear(derivedKey, 0, derivedKey.Length);
            }
        }

        public string DecryptText(string encryptedTextWithMetadata, string password)
        {
            if (string.IsNullOrWhiteSpace(encryptedTextWithMetadata))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encryptedTextWithMetadata));
            }

            return DecryptData(_encoder.Decode(encryptedTextWithMetadata), password).ToUTF8String();
        }

        #region Private methods

        private static Pbkdf2Configuration GetKeyDerivationConfiguration(Pbkdf2PseudoRandomFunction pseudoRandomFunction, int iterations)
            => new Pbkdf2Configuration(pseudoRandomFunction, iterations, Pbkdf2Configuration.MinimumSaltSize, _derivedKeySize);

        private byte[] BuildHeader(byte[] salt)
        {
            var header = new byte[_headerFixedSize + salt.Length];

            header[0] = _formatVersion;
            header[1] = (byte)_configuration.PseudoRandomFunction;
            header[2] = (byte)(_configuration.Iterations & 0xFF);
            header[3] = (byte)((_configuration.Iterations >> 8) & 0xFF);
            header[4] = (byte)((_configuration.Iterations >> 16) & 0xFF);
            header[5] = (byte)((_configuration.Iterations >> 24) & 0xFF);
            header[6] = (byte)salt.Length;

            Array.Copy(salt, 0, header, _headerFixedSize, salt.Length);

            return header;
        }

        private static (Pbkdf2PseudoRandomFunction PseudoRandomFunction, int Iterations, byte[] Salt, int HeaderSize) ParseHeader(
            byte[] encryptedDataWithMetadata)
        {
            if (encryptedDataWithMetadata.Length < _headerFixedSize + 1 ||
                encryptedDataWithMetadata[0] != _formatVersion ||
                !Enum.IsDefined(typeof(Pbkdf2PseudoRandomFunction), (int)encryptedDataWithMetadata[1]))
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(encryptedDataWithMetadata));
            }

            var pseudoRandomFunction = (Pbkdf2PseudoRandomFunction)encryptedDataWithMetadata[1];
            var iterations =
                encryptedDataWithMetadata[2] |
                (encryptedDataWithMetadata[3] << 8) |
                (encryptedDataWithMetadata[4] << 16) |
                (encryptedDataWithMetadata[5] << 24);
            var saltSize = (int)encryptedDataWithMetadata[6];
            var headerSize = _headerFixedSize + saltSize;

            if (iterations <= 0 || saltSize < Pbkdf2Configuration.MinimumSaltSize || encryptedDataWithMetadata.Length <= headerSize)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(encryptedDataWithMetadata));
            }

            var salt = new byte[saltSize];

            Array.Copy(encryptedDataWithMetadata, _headerFixedSize, salt, 0, saltSize);

            return (pseudoRandomFunction, iterations, salt, headerSize);
        }

        private static void CheckPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(password));
            }
        }

        #endregion Private methods
    }
}
