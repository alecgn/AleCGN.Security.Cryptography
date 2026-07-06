using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;
#if NET8_0_OR_GREATER
using System.Security.Cryptography;
#else
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    /// <summary>
    /// HKDF (RFC 5869) key derivation: expands already-strong input key material into one or more keys.
    /// For password-based derivation use <see cref="Pbkdf2"/> or <see cref="Argon2id"/> instead.
    /// </summary>
    public class Hkdf : IHkdf
    {
        private readonly IEncoder _encoder;
        private readonly HashAlgorithmKind _hashAlgorithmKind;

        public Hkdf(IEncoder encoder) : this(encoder, HashAlgorithmKind.SHA256) { }

        public Hkdf(IEncoder encoder, HashAlgorithmKind hashAlgorithmKind)
        {
            _encoder = encoder;
            _hashAlgorithmKind = hashAlgorithmKind;
        }

        public byte[] DeriveKey(byte[] inputKeyMaterial, int derivedKeySize, byte[] salt = null, byte[] info = null)
        {
            if (inputKeyMaterial is null || inputKeyMaterial.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(inputKeyMaterial));
            }

            if (derivedKeySize <= 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentOutOfRange, nameof(derivedKeySize));
            }

#if NET8_0_OR_GREATER
            return HKDF.DeriveKey(
                DigestHelper.GetHashAlgorithmName(_hashAlgorithmKind),
                inputKeyMaterial,
                derivedKeySize,
                salt,
                info
            );
#else
            var generator = new HkdfBytesGenerator(DigestHelper.CreateDigest(_hashAlgorithmKind));

            generator.Init(new HkdfParameters(inputKeyMaterial, salt, info));

            var derivedKey = new byte[derivedKeySize];

            generator.GenerateBytes(derivedKey, 0, derivedKeySize);

            return derivedKey;
#endif
        }

        public string DeriveTextKey(string inputKeyMaterial, int derivedKeySize, string salt = null, string info = null)
        {
            if (string.IsNullOrWhiteSpace(inputKeyMaterial))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(inputKeyMaterial));
            }

            var derivedKey = DeriveKey(
                inputKeyMaterial.ToUTF8Bytes(),
                derivedKeySize,
                string.IsNullOrEmpty(salt) ? null : salt.ToUTF8Bytes(),
                string.IsNullOrEmpty(info) ? null : info.ToUTF8Bytes()
            );

            return _encoder.Encode(derivedKey);
        }

        public Task<byte[]> DeriveKeyAsync(
            byte[] inputKeyMaterial,
            int derivedKeySize,
            byte[] salt = null,
            byte[] info = null,
            CancellationToken cancellationToken = default)
            => Task.Run(() => DeriveKey(inputKeyMaterial, derivedKeySize, salt, info), cancellationToken);

        public Task<string> DeriveTextKeyAsync(
            string inputKeyMaterial,
            int derivedKeySize,
            string salt = null,
            string info = null,
            CancellationToken cancellationToken = default)
            => Task.Run(() => DeriveTextKey(inputKeyMaterial, derivedKeySize, salt, info), cancellationToken);
    }
}
