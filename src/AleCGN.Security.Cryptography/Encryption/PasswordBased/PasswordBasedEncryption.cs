using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.KeyDerivation;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.PasswordBased
{
    /// <summary>
    /// Password-based encryption combining PBKDF2 key derivation with AES-GCM-256.
    /// Payloads are self-describing (algorithm, KDF parameters and salt are explicit fields — see
    /// PayloadFormat): "$pbe-aes256-gcm$v=1$pbkdf2-sha256,i=600000$&lt;salt&gt;$&lt;nonce&gt;$&lt;tag&gt;$&lt;ciphertext&gt;".
    /// The KDF parameters and salt are bound as associated data, so tampering with them causes
    /// decryption to fail, and data encrypted with older configurations remains decryptable.
    /// </summary>
    public class PasswordBasedEncryption : IPasswordBasedEncryption
    {
        private const int _fieldCount = 5;        // kdf parameters | salt | nonce | tag | ciphertext
        private const int _kdfFieldSize = 5;      // prf(1) + iterations(4, little-endian)
        private const int _derivedKeySize = 32;
        private const string _pbkdf2ParameterPrefix = "pbkdf2-";
        private const string _iterationsParameterPrefix = "i=";

        private readonly IEncoder _encoder;
        private readonly Pbkdf2Configuration _configuration;

        public PasswordBasedEncryption(IEncoder encoder) : this(encoder, Pbkdf2Configuration.Default) { }

        public PasswordBasedEncryption(IEncoder encoder, Pbkdf2Configuration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            _encoder = encoder;
            _configuration = configuration;
        }

        #region Public methods

        public byte[] EncryptData(byte[] data, string password)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            CheckPassword(password);

            var pbkdf2 = new Pbkdf2(_encoder, new Pbkdf2Configuration(
                _configuration.PseudoRandomFunction, _configuration.Iterations, _configuration.SaltSize, _derivedKeySize));
            var derivedKey = pbkdf2.DeriveKey(password.ToUTF8Bytes(), out var salt);

            try
            {
                var associatedData = BuildAssociatedData(_configuration.PseudoRandomFunction, _configuration.Iterations, salt);

                using (var aesGcm256 = new AesGcm256(_encoder, derivedKey))
                {
                    var aesPayload = aesGcm256.EncryptData(data, associatedData);
                    var aesFields = PayloadFormat.GetFields(
                        aesPayload,
                        PayloadFormat.ParseBinary(aesPayload, PayloadAlgorithms.Aes256Gcm, 3, nameof(data)));

                    return PayloadFormat.BuildBinary(
                        PayloadAlgorithms.PasswordBasedAes256Gcm,
                        BuildKdfField(_configuration.PseudoRandomFunction, _configuration.Iterations),
                        salt,
                        aesFields[0],   // nonce
                        aesFields[1],   // tag
                        aesFields[2]    // ciphertext
                    );
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

            var payload = EncryptData(text.ToUTF8Bytes(), password);
            var fields = PayloadFormat.GetFields(
                payload,
                PayloadFormat.ParseBinary(payload, PayloadAlgorithms.PasswordBasedAes256Gcm, _fieldCount, nameof(text)));

            var parameters = string.Format(
                CultureInfo.InvariantCulture,
                "{0}{1},{2}{3}",
                _pbkdf2ParameterPrefix,
                GetPrfToken(_configuration.PseudoRandomFunction),
                _iterationsParameterPrefix,
                _configuration.Iterations);

            return PayloadFormat.BuildString(
                PayloadAlgorithms.PasswordBasedAes256GcmName,
                parameters,
                fields[1],  // salt
                fields[2],  // nonce
                fields[3],  // tag
                fields[4]   // ciphertext
            );
        }

        public byte[] DecryptData(byte[] encryptedDataWithMetadata, string password)
        {
            if (encryptedDataWithMetadata is null || encryptedDataWithMetadata.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(encryptedDataWithMetadata));
            }

            CheckPassword(password);

            var fields = PayloadFormat.GetFields(
                encryptedDataWithMetadata,
                PayloadFormat.ParseBinary(
                    encryptedDataWithMetadata, PayloadAlgorithms.PasswordBasedAes256Gcm, _fieldCount, nameof(encryptedDataWithMetadata)));

            var (pseudoRandomFunction, iterations) = ParseKdfField(fields[0], nameof(encryptedDataWithMetadata));

            return DecryptCore(pseudoRandomFunction, iterations, fields[1], fields[2], fields[3], fields[4], password,
                nameof(encryptedDataWithMetadata));
        }

        public string DecryptText(string encryptedTextWithMetadata, string password)
        {
            if (string.IsNullOrWhiteSpace(encryptedTextWithMetadata))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encryptedTextWithMetadata));
            }

            CheckPassword(password);

            var (parameters, fields) = PayloadFormat.ParseString(
                encryptedTextWithMetadata, PayloadAlgorithms.PasswordBasedAes256GcmName, _fieldCount - 1,
                hasParameters: true, nameof(encryptedTextWithMetadata));

            var (pseudoRandomFunction, iterations) = ParseParameters(parameters, nameof(encryptedTextWithMetadata));

            return DecryptCore(pseudoRandomFunction, iterations, fields[0], fields[1], fields[2], fields[3], password,
                nameof(encryptedTextWithMetadata)).ToUTF8String();
        }

        public Task<byte[]> EncryptDataAsync(byte[] data, string password, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptData(data, password), cancellationToken);

        public Task<string> EncryptTextAsync(string text, string password, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptText(text, password), cancellationToken);

        public Task<byte[]> DecryptDataAsync(byte[] encryptedDataWithMetadata, string password, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptData(encryptedDataWithMetadata, password), cancellationToken);

        public Task<string> DecryptTextAsync(string encryptedTextWithMetadata, string password, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptText(encryptedTextWithMetadata, password), cancellationToken);

        #endregion Public methods


        #region Private methods

        private byte[] DecryptCore(
            Pbkdf2PseudoRandomFunction pseudoRandomFunction,
            int iterations,
            byte[] salt,
            byte[] nonce,
            byte[] tag,
            byte[] ciphertext,
            string password,
            string paramName)
        {
            if (salt.Length < Pbkdf2Configuration.MinimumSaltSize)
            {
                throw PayloadFormat.CreateInvalidPayloadException(paramName);
            }

            var pbkdf2 = new Pbkdf2(_encoder, new Pbkdf2Configuration(
                pseudoRandomFunction, iterations, Pbkdf2Configuration.MinimumSaltSize, _derivedKeySize));
            var derivedKey = pbkdf2.DeriveKey(password.ToUTF8Bytes(), salt);

            try
            {
                var associatedData = BuildAssociatedData(pseudoRandomFunction, iterations, salt);
                var aesPayload = PayloadFormat.BuildBinary(PayloadAlgorithms.Aes256Gcm, nonce, tag, ciphertext);

                using (var aesGcm256 = new AesGcm256(_encoder, derivedKey))
                {
                    return aesGcm256.DecryptData(aesPayload, associatedData);
                }
            }
            finally
            {
                Array.Clear(derivedKey, 0, derivedKey.Length);
            }
        }

        /// <summary>
        /// Canonical associated data binding the KDF parameters and salt to the ciphertext,
        /// identical for payloads produced by the binary and the string APIs.
        /// </summary>
        private static byte[] BuildAssociatedData(Pbkdf2PseudoRandomFunction pseudoRandomFunction, int iterations, byte[] salt)
        {
            var associatedData = new byte[2 + _kdfFieldSize + salt.Length];

            associatedData[0] = PayloadFormat.FormatVersion;
            associatedData[1] = PayloadAlgorithms.PasswordBasedAes256Gcm;

            var kdfField = BuildKdfField(pseudoRandomFunction, iterations);

            Array.Copy(kdfField, 0, associatedData, 2, _kdfFieldSize);
            Array.Copy(salt, 0, associatedData, 2 + _kdfFieldSize, salt.Length);

            return associatedData;
        }

        private static byte[] BuildKdfField(Pbkdf2PseudoRandomFunction pseudoRandomFunction, int iterations)
            => new[]
            {
                (byte)pseudoRandomFunction,
                (byte)(iterations & 0xFF),
                (byte)((iterations >> 8) & 0xFF),
                (byte)((iterations >> 16) & 0xFF),
                (byte)((iterations >> 24) & 0xFF)
            };

        private static (Pbkdf2PseudoRandomFunction PseudoRandomFunction, int Iterations) ParseKdfField(byte[] kdfField, string paramName)
        {
            if (kdfField.Length != _kdfFieldSize || !Enum.IsDefined(typeof(Pbkdf2PseudoRandomFunction), (int)kdfField[0]))
            {
                throw PayloadFormat.CreateInvalidPayloadException(paramName);
            }

            var iterations = kdfField[1] | (kdfField[2] << 8) | (kdfField[3] << 16) | (kdfField[4] << 24);

            if (iterations <= 0)
            {
                throw PayloadFormat.CreateInvalidPayloadException(paramName);
            }

            return ((Pbkdf2PseudoRandomFunction)kdfField[0], iterations);
        }

        private static (Pbkdf2PseudoRandomFunction PseudoRandomFunction, int Iterations) ParseParameters(string parameters, string paramName)
        {
            var parts = parameters.Split(',');

            if (parts.Length != 2 ||
                !parts[0].StartsWith(_pbkdf2ParameterPrefix, StringComparison.Ordinal) ||
                !parts[1].StartsWith(_iterationsParameterPrefix, StringComparison.Ordinal) ||
                !int.TryParse(parts[1].Substring(_iterationsParameterPrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var iterations) ||
                iterations <= 0)
            {
                throw PayloadFormat.CreateInvalidPayloadException(paramName);
            }

            return (ParsePrfToken(parts[0].Substring(_pbkdf2ParameterPrefix.Length), paramName), iterations);
        }

        private static string GetPrfToken(Pbkdf2PseudoRandomFunction pseudoRandomFunction)
        {
            switch (pseudoRandomFunction)
            {
                case Pbkdf2PseudoRandomFunction.HMACSHA1:
                    return "sha1";
                case Pbkdf2PseudoRandomFunction.HMACSHA256:
                    return "sha256";
                case Pbkdf2PseudoRandomFunction.HMACSHA384:
                    return "sha384";
                default:
                    return "sha512";
            }
        }

        private static Pbkdf2PseudoRandomFunction ParsePrfToken(string token, string paramName)
        {
            switch (token)
            {
                case "sha1":
                    return Pbkdf2PseudoRandomFunction.HMACSHA1;
                case "sha256":
                    return Pbkdf2PseudoRandomFunction.HMACSHA256;
                case "sha384":
                    return Pbkdf2PseudoRandomFunction.HMACSHA384;
                case "sha512":
                    return Pbkdf2PseudoRandomFunction.HMACSHA512;
                default:
                    throw PayloadFormat.CreateInvalidPayloadException(paramName);
            }
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
