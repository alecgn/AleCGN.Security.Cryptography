using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    /// <summary>
    /// Argon2id (RFC 9106) key derivation, the state-of-the-art algorithm for password hashing.
    /// The memory size, iterations, parallelism, salt size and derived key size are driven by the
    /// <see cref="Argon2idConfiguration"/> provided in the constructor.
    /// </summary>
    public class Argon2id : IArgon2id
    {
        private readonly IEncoder _encoder;
        private readonly Argon2idConfiguration _configuration;

        public Argon2id(IEncoder encoder) : this(encoder, Argon2idConfiguration.Default) { }

        public Argon2id(IEncoder encoder, Argon2idConfiguration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            _encoder = encoder;
            _configuration = configuration;
        }

        public byte[] DeriveKey(byte[] password, out byte[] salt)
        {
            salt = CryptographyHelper.GenerateSecureRandomBytes(_configuration.SaltSize);

            return DeriveKey(password, salt);
        }

        public byte[] DeriveKey(byte[] password, byte[] salt)
        {
            CheckInputData(password, nameof(password));
            CheckInputData(salt, nameof(salt));

            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithMemoryAsKB(_configuration.MemorySizeInKB)
                .WithIterations(_configuration.Iterations)
                .WithParallelism(_configuration.Parallelism)
                .WithSalt(salt)
                .Build();

            var generator = new Argon2BytesGenerator();

            generator.Init(parameters);

            var derivedKey = new byte[_configuration.DerivedKeySize];

            generator.GenerateBytes(password, derivedKey, 0, derivedKey.Length);

            return derivedKey;
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
    }
}
