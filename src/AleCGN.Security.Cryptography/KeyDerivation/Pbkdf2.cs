using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;
#if NETSTANDARD2_0
using AleCGN.Security.Cryptography.Constants;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    /// <summary>
    /// PBKDF2 (RFC 8018) key derivation. The pseudo-random function, iteration count, salt size and
    /// derived key size are driven by the <see cref="Pbkdf2Configuration"/> provided in the constructor.
    /// </summary>
    public class Pbkdf2 : IPbkdf2
    {
        #region Fields

        private readonly IEncoder _encoder;
        private readonly Pbkdf2Configuration _configuration;

        #endregion Fields


        #region Constructors

        public Pbkdf2(IEncoder encoder) : this(encoder, Pbkdf2Configuration.Default) { }

        public Pbkdf2(IEncoder encoder, Pbkdf2Configuration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            _encoder = encoder;
            _configuration = configuration;
        }

        #endregion Constructors


        #region Public methods

        public byte[] DeriveKey(byte[] password, out byte[] salt)
        {
            salt = CryptographyHelper.GenerateSecureRandomBytes(_configuration.SaltSize);

            return DeriveKey(password, salt);
        }

        public byte[] DeriveKey(byte[] password, byte[] salt)
        {
            CheckInputData(password, nameof(password));
            CheckInputData(salt, nameof(salt));

            return DeriveKeyInternal(password, salt);
        }

        public string DeriveTextKey(string password, out string encodedSalt)
        {
            CheckInputText(password, nameof(password));

            var derivedKey = DeriveKey(password.ToUTF8Bytes(), out var salt);

            encodedSalt = _encoder.Encode(salt);

            return _encoder.Encode(derivedKey);
        }

        public string DeriveTextKey(string password, string encodedSalt)
        {
            CheckInputText(password, nameof(password));
            CheckInputText(encodedSalt, nameof(encodedSalt));

            var derivedKey = DeriveKey(password.ToUTF8Bytes(), _encoder.Decode(encodedSalt));

            return _encoder.Encode(derivedKey);
        }

        public bool VerifyKey(byte[] password, byte[] salt, byte[] expectedDerivedKey)
        {
            CheckInputData(expectedDerivedKey, nameof(expectedDerivedKey));

            var derivedKey = DeriveKey(password, salt);

            return CryptographyHelper.FixedTimeEquals(derivedKey, expectedDerivedKey);
        }

        public bool VerifyTextKey(string password, string encodedSalt, string encodedExpectedDerivedKey)
        {
            CheckInputText(password, nameof(password));
            CheckInputText(encodedSalt, nameof(encodedSalt));
            CheckInputText(encodedExpectedDerivedKey, nameof(encodedExpectedDerivedKey));

            return VerifyKey(
                password.ToUTF8Bytes(),
                _encoder.Decode(encodedSalt),
                _encoder.Decode(encodedExpectedDerivedKey)
            );
        }

        public Task<KeyDerivationResult> DeriveKeyAsync(byte[] password, CancellationToken cancellationToken = default)
            => Task.Run(() =>
            {
                var key = DeriveKey(password, out var salt);

                return new KeyDerivationResult(key, salt);
            }, cancellationToken);

        public Task<byte[]> DeriveKeyAsync(byte[] password, byte[] salt, CancellationToken cancellationToken = default)
            => Task.Run(() => DeriveKey(password, salt), cancellationToken);

        public Task<EncodedKeyDerivationResult> DeriveTextKeyAsync(string password, CancellationToken cancellationToken = default)
            => Task.Run(() =>
            {
                var encodedKey = DeriveTextKey(password, out var encodedSalt);

                return new EncodedKeyDerivationResult(encodedKey, encodedSalt);
            }, cancellationToken);

        public Task<string> DeriveTextKeyAsync(string password, string encodedSalt, CancellationToken cancellationToken = default)
            => Task.Run(() => DeriveTextKey(password, encodedSalt), cancellationToken);

        public Task<bool> VerifyKeyAsync(byte[] password, byte[] salt, byte[] expectedDerivedKey, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyKey(password, salt, expectedDerivedKey), cancellationToken);

        public Task<bool> VerifyTextKeyAsync(string password, string encodedSalt, string encodedExpectedDerivedKey, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyTextKey(password, encodedSalt, encodedExpectedDerivedKey), cancellationToken);

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

#if NETSTANDARD2_0
        private byte[] DeriveKeyInternal(byte[] password, byte[] salt)
        {
            var generator = new Pkcs5S2ParametersGenerator(CreateDigest());

            generator.Init(password, salt, _configuration.Iterations);

            var keyParameter = (KeyParameter)generator.GenerateDerivedMacParameters(
                _configuration.DerivedKeySize * ConstantValues.BitsPerByte);

            return keyParameter.GetKey();
        }

        private IDigest CreateDigest()
        {
            switch (_configuration.PseudoRandomFunction)
            {
                case Pbkdf2PseudoRandomFunction.HMACSHA1:
                    return new Sha1Digest();
                case Pbkdf2PseudoRandomFunction.HMACSHA256:
                    return new Sha256Digest();
                case Pbkdf2PseudoRandomFunction.HMACSHA384:
                    return new Sha384Digest();
                case Pbkdf2PseudoRandomFunction.HMACSHA512:
                    return new Sha512Digest();
                default:
                    throw new CryptographicException($"Unsupported pseudo-random function: {_configuration.PseudoRandomFunction}.");
            }
        }
#else
        private byte[] DeriveKeyInternal(byte[] password, byte[] salt)
        {
#if NET8_0_OR_GREATER
            return Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                _configuration.Iterations,
                GetHashAlgorithmName(),
                _configuration.DerivedKeySize
            );
#else
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, _configuration.Iterations, GetHashAlgorithmName()))
            {
                return rfc2898DeriveBytes.GetBytes(_configuration.DerivedKeySize);
            }
#endif
        }

        private HashAlgorithmName GetHashAlgorithmName()
        {
            switch (_configuration.PseudoRandomFunction)
            {
                case Pbkdf2PseudoRandomFunction.HMACSHA1:
                    return HashAlgorithmName.SHA1;
                case Pbkdf2PseudoRandomFunction.HMACSHA256:
                    return HashAlgorithmName.SHA256;
                case Pbkdf2PseudoRandomFunction.HMACSHA384:
                    return HashAlgorithmName.SHA384;
                case Pbkdf2PseudoRandomFunction.HMACSHA512:
                    return HashAlgorithmName.SHA512;
                default:
                    throw new CryptographicException($"Unsupported pseudo-random function: {_configuration.PseudoRandomFunction}.");
            }
        }
#endif

        #endregion Private methods
    }
}
