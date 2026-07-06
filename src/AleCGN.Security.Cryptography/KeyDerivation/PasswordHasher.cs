using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.Globalization;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    /// <summary>
    /// Password hashing with self-contained hash strings in the PHC format:
    /// "$argon2id$v=19$m=19456,t=2,p=1$&lt;salt&gt;$&lt;hash&gt;" or "$pbkdf2-sha256$i=600000$&lt;salt&gt;$&lt;hash&gt;".
    /// The salt and all parameters are embedded in the produced string, so a single value can be stored
    /// and verified later, even after the configured parameters change (use <see cref="NeedsRehash"/> to
    /// detect stored hashes with outdated parameters).
    /// </summary>
    public class PasswordHasher : IPasswordHasher
    {
        private const string _argon2idIdentifier = "argon2id";
        private const string _pbkdf2IdentifierPrefix = "pbkdf2-";
        private const int _argon2Version = 19;

        private readonly Pbkdf2Configuration _pbkdf2Configuration;
        private readonly Argon2idConfiguration _argon2idConfiguration;

        /// <summary>
        /// Uses Argon2id with the OWASP-recommended default configuration.
        /// </summary>
        public PasswordHasher() : this(Argon2idConfiguration.Default) { }

        public PasswordHasher(Argon2idConfiguration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            _argon2idConfiguration = configuration;
        }

        public PasswordHasher(Pbkdf2Configuration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            _pbkdf2Configuration = configuration;
        }

        public string HashPassword(string password)
        {
            CheckInputText(password, nameof(password));

            var salt = CryptographyHelper.GenerateSecureRandomBytes(
                _argon2idConfiguration?.SaltSize ?? _pbkdf2Configuration.SaltSize);

            if (_argon2idConfiguration != null)
            {
                var derivedKey = DeriveArgon2id(password, salt, _argon2idConfiguration);

                return string.Format(
                    CultureInfo.InvariantCulture,
                    "${0}$v={1}$m={2},t={3},p={4}${5}${6}",
                    _argon2idIdentifier,
                    _argon2Version,
                    _argon2idConfiguration.MemorySizeInKB,
                    _argon2idConfiguration.Iterations,
                    _argon2idConfiguration.Parallelism,
                    ToUnpaddedBase64(salt),
                    ToUnpaddedBase64(derivedKey)
                );
            }
            else
            {
                var derivedKey = DerivePbkdf2(password, salt, _pbkdf2Configuration);

                return string.Format(
                    CultureInfo.InvariantCulture,
                    "${0}{1}$i={2}${3}${4}",
                    _pbkdf2IdentifierPrefix,
                    GetPbkdf2PrfIdentifier(_pbkdf2Configuration.PseudoRandomFunction),
                    _pbkdf2Configuration.Iterations,
                    ToUnpaddedBase64(salt),
                    ToUnpaddedBase64(derivedKey)
                );
            }
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
            CheckInputText(password, nameof(password));

            var parsedHash = ParseHashedPassword(hashedPassword);

            byte[] computedKey;

            if (parsedHash.IsArgon2id)
            {
                var configuration = new Argon2idConfiguration(
                    parsedHash.MemorySizeInKB,
                    parsedHash.Iterations,
                    parsedHash.Parallelism,
                    Pbkdf2Configuration.MinimumSaltSize,
                    parsedHash.ExpectedKey.Length);

                computedKey = DeriveArgon2id(password, parsedHash.Salt, configuration);
            }
            else
            {
                var configuration = new Pbkdf2Configuration(
                    parsedHash.PseudoRandomFunction,
                    parsedHash.Iterations,
                    Pbkdf2Configuration.MinimumSaltSize,
                    parsedHash.ExpectedKey.Length);

                computedKey = DerivePbkdf2(password, parsedHash.Salt, configuration);
            }

            return CryptographyHelper.FixedTimeEquals(computedKey, parsedHash.ExpectedKey);
        }

        public bool NeedsRehash(string hashedPassword)
        {
            var parsedHash = ParseHashedPassword(hashedPassword);

            if (_argon2idConfiguration != null)
            {
                return !parsedHash.IsArgon2id ||
                    parsedHash.MemorySizeInKB != _argon2idConfiguration.MemorySizeInKB ||
                    parsedHash.Iterations != _argon2idConfiguration.Iterations ||
                    parsedHash.Parallelism != _argon2idConfiguration.Parallelism ||
                    parsedHash.Salt.Length != _argon2idConfiguration.SaltSize ||
                    parsedHash.ExpectedKey.Length != _argon2idConfiguration.DerivedKeySize;
            }

            return parsedHash.IsArgon2id ||
                parsedHash.PseudoRandomFunction != _pbkdf2Configuration.PseudoRandomFunction ||
                parsedHash.Iterations != _pbkdf2Configuration.Iterations ||
                parsedHash.Salt.Length != _pbkdf2Configuration.SaltSize ||
                parsedHash.ExpectedKey.Length != _pbkdf2Configuration.DerivedKeySize;
        }

        #region Private methods

        private class ParsedPasswordHash
        {
            public bool IsArgon2id;
            public Pbkdf2PseudoRandomFunction PseudoRandomFunction;
            public int MemorySizeInKB;
            public int Iterations;
            public int Parallelism;
            public byte[] Salt;
            public byte[] ExpectedKey;
        }

        private static byte[] DeriveArgon2id(string password, byte[] salt, Argon2idConfiguration configuration)
        {
            var argon2id = new Argon2id(new Base64Encoder(), configuration);

            return argon2id.DeriveKey(password.ToUTF8Bytes(), salt);
        }

        private static byte[] DerivePbkdf2(string password, byte[] salt, Pbkdf2Configuration configuration)
        {
            var pbkdf2 = new Pbkdf2(new Base64Encoder(), configuration);

            return pbkdf2.DeriveKey(password.ToUTF8Bytes(), salt);
        }

        private static ParsedPasswordHash ParseHashedPassword(string hashedPassword)
        {
            if (string.IsNullOrWhiteSpace(hashedPassword))
            {
                throw CreateInvalidHashException(nameof(hashedPassword));
            }

            var parts = hashedPassword.Split('$');

            // Expected: "" | identifier | parameters... | salt | hash
            if (parts.Length < 5 || parts[0].Length != 0)
            {
                throw CreateInvalidHashException(nameof(hashedPassword));
            }

            var parsedHash = new ParsedPasswordHash
            {
                Salt = FromUnpaddedBase64(parts[parts.Length - 2], nameof(hashedPassword)),
                ExpectedKey = FromUnpaddedBase64(parts[parts.Length - 1], nameof(hashedPassword))
            };

            if (parts[1] == _argon2idIdentifier)
            {
                // $argon2id$v=19$m=...,t=...,p=...$salt$hash
                if (parts.Length != 6 || parts[2] != $"v={_argon2Version}")
                {
                    throw CreateInvalidHashException(nameof(hashedPassword));
                }

                parsedHash.IsArgon2id = true;

                foreach (var parameter in parts[3].Split(','))
                {
                    var keyValue = parameter.Split('=');

                    if (keyValue.Length != 2 || !int.TryParse(keyValue[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
                    {
                        throw CreateInvalidHashException(nameof(hashedPassword));
                    }

                    switch (keyValue[0])
                    {
                        case "m":
                            parsedHash.MemorySizeInKB = value;
                            break;
                        case "t":
                            parsedHash.Iterations = value;
                            break;
                        case "p":
                            parsedHash.Parallelism = value;
                            break;
                        default:
                            throw CreateInvalidHashException(nameof(hashedPassword));
                    }
                }

                if (parsedHash.MemorySizeInKB <= 0 || parsedHash.Iterations <= 0 || parsedHash.Parallelism <= 0)
                {
                    throw CreateInvalidHashException(nameof(hashedPassword));
                }
            }
            else if (parts[1].StartsWith(_pbkdf2IdentifierPrefix, StringComparison.Ordinal))
            {
                // $pbkdf2-sha256$i=...$salt$hash
                if (parts.Length != 5)
                {
                    throw CreateInvalidHashException(nameof(hashedPassword));
                }

                parsedHash.PseudoRandomFunction = ParsePbkdf2PrfIdentifier(
                    parts[1].Substring(_pbkdf2IdentifierPrefix.Length), nameof(hashedPassword));

                var iterationsPart = parts[2];

                if (!iterationsPart.StartsWith("i=", StringComparison.Ordinal) ||
                    !int.TryParse(iterationsPart.Substring(2), NumberStyles.None, CultureInfo.InvariantCulture, out var iterations) ||
                    iterations <= 0)
                {
                    throw CreateInvalidHashException(nameof(hashedPassword));
                }

                parsedHash.Iterations = iterations;
            }
            else
            {
                throw CreateInvalidHashException(nameof(hashedPassword));
            }

            return parsedHash;
        }

        private static string GetPbkdf2PrfIdentifier(Pbkdf2PseudoRandomFunction pseudoRandomFunction)
        {
            switch (pseudoRandomFunction)
            {
                case Pbkdf2PseudoRandomFunction.HMACSHA1:
                    return "sha1";
                case Pbkdf2PseudoRandomFunction.HMACSHA256:
                    return "sha256";
                case Pbkdf2PseudoRandomFunction.HMACSHA384:
                    return "sha384";
                case Pbkdf2PseudoRandomFunction.HMACSHA512:
                    return "sha512";
                default:
                    throw new ArgumentOutOfRangeException(nameof(pseudoRandomFunction));
            }
        }

        private static Pbkdf2PseudoRandomFunction ParsePbkdf2PrfIdentifier(string identifier, string paramName)
        {
            switch (identifier)
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
                    throw CreateInvalidHashException(paramName);
            }
        }

        private static string ToUnpaddedBase64(byte[] data)
            => Convert.ToBase64String(data).TrimEnd('=');

        private static byte[] FromUnpaddedBase64(string base64String, string paramName)
        {
            var paddingLength = (4 - (base64String.Length % 4)) % 4;

            if (base64String.Length == 0 || paddingLength == 3)
            {
                throw CreateInvalidHashException(paramName);
            }

            try
            {
                return Convert.FromBase64String(base64String + new string('=', paddingLength));
            }
            catch (FormatException)
            {
                throw CreateInvalidHashException(paramName);
            }
        }

        private static ArgumentException CreateInvalidHashException(string paramName)
            => CreateFormattedArgumentException(LibraryResources.Validation_InvalidPasswordHash, paramName);

        private static void CheckInputText(string inputText, string paramName)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, paramName);
            }
        }

        #endregion Private methods
    }
}
