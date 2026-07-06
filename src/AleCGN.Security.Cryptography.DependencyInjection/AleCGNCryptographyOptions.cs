using AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged;
using AleCGN.Security.Cryptography.KeyDerivation;

namespace AleCGN.Security.Cryptography.DependencyInjection
{
    public enum EncoderKind
    {
        Base64,
        Base64Url,
        Base32,
        Hexadecimal
    }

    public class AleCGNCryptographyOptions
    {
        /// <summary>
        /// Encoder used by all registered services to encode/decode strings. Default: Base64.
        /// </summary>
        public EncoderKind Encoder { get; set; } = EncoderKind.Base64;

        /// <summary>
        /// PBKDF2 configuration used by IPbkdf2 and IPasswordBasedEncryption. Default: OWASP recommendation.
        /// </summary>
        public Pbkdf2Configuration Pbkdf2Configuration { get; set; } = Pbkdf2Configuration.Default;

        /// <summary>
        /// Argon2id configuration used by IArgon2id and IPasswordHasher. Default: OWASP recommendation.
        /// </summary>
        public Argon2idConfiguration Argon2idConfiguration { get; set; } = Argon2idConfiguration.Default;

        /// <summary>
        /// When true, IPasswordHasher uses PBKDF2 instead of Argon2id.
        /// </summary>
        public bool UsePbkdf2ForPasswordHashing { get; set; }

        /// <summary>
        /// Optional keys: when set, the corresponding services are registered already keyed;
        /// otherwise they are registered keyless and SetOrUpdateKey(...) must be called before use.
        /// </summary>
        public byte[] AesGcm128Key { get; set; }

        public byte[] AesGcm192Key { get; set; }

        public byte[] AesGcm256Key { get; set; }

        public byte[] ChaCha20Poly1305Key { get; set; }

        public byte[] HmacKey { get; set; }

        /// <summary>
        /// When set, IDataProtection is registered (Windows-only, DPAPI).
        /// </summary>
        public DataProtectionConfiguration DataProtectionConfiguration { get; set; }

        /// <summary>
        /// Optional PEM keys: when set, IRsaOaepEncryption / IRsaPssSigner / IEcdsaSigner are registered with them.
        /// </summary>
        public string RsaPublicKeyPem { get; set; }

        public string RsaPrivateKeyPem { get; set; }

        public string EcdsaPublicKeyPem { get; set; }

        public string EcdsaPrivateKeyPem { get; set; }

        public int FileEncryptionChunkSizeInKB { get; set; } = 1024;
    }
}
