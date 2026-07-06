using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.PasswordBased;
using AleCGN.Security.Cryptography.KeyDerivation;
using System;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encryption
{
    public class PasswordBasedEncryptionTests
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private static readonly Pbkdf2Configuration _fastConfiguration =
            new Pbkdf2Configuration(Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 1_000, saltSize: 16, derivedKeySize: 32);

        private static PasswordBasedEncryption Create() => new PasswordBasedEncryption(_encoder, _fastConfiguration);

        [Fact]
        public void EncryptDecrypt_DataAndText_Roundtrip()
        {
            var pbe = Create();
            var data = Utf8("secret payload");

            Assert.Equal(data, pbe.DecryptData(pbe.EncryptData(data, "password"), "password"));
            Assert.Equal("secret text", pbe.DecryptText(pbe.EncryptText("secret text", "password"), "password"));
        }

        [Fact]
        public void Decrypt_WrongPassword_Fails()
        {
            var pbe = Create();
            var encrypted = pbe.EncryptText("secret", "correct password");

            Assert.ThrowsAny<Exception>(() => pbe.DecryptText(encrypted, "wrong password"));
        }

        [Fact]
        public void Decrypt_UsesParametersEmbeddedInPayload_NotCurrentConfiguration()
        {
            // Encrypt with one configuration, decrypt with an instance configured differently
            var oldInstance = new PasswordBasedEncryption(_encoder, new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA1, iterations: 500, saltSize: 16, derivedKeySize: 32));
            var newInstance = new PasswordBasedEncryption(_encoder, new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA512, iterations: 2_000, saltSize: 32, derivedKeySize: 32));

            var encrypted = oldInstance.EncryptText("secret", "password");

            Assert.Equal("secret", newInstance.DecryptText(encrypted, "password"));
        }

        [Fact]
        public void TamperedHeader_FailsAuthentication()
        {
            var pbe = Create();
            var payload = pbe.EncryptData(Utf8("secret"), "password");

            // Lower the iteration count in the header (bytes 2..5); header is bound as AAD
            payload[2] ^= 0xFF;

            Assert.ThrowsAny<Exception>(() => pbe.DecryptData(payload, "password"));
        }

        [Fact]
        public void TamperedCiphertext_FailsAuthentication()
        {
            var pbe = Create();
            var payload = pbe.EncryptData(Utf8("secret"), "password");

            payload[payload.Length - 1] ^= 0xFF;

            Assert.ThrowsAny<Exception>(() => pbe.DecryptData(payload, "password"));
        }

        [Theory]
        [InlineData(new byte[] { 9, 9, 9 })]                        // too short / wrong version
        [InlineData(new byte[] { 1, 99, 0, 0, 0, 0, 16, 0, 0 })]    // invalid PRF value
        public void Decrypt_InvalidPayload_Throws(byte[] payload)
        {
            var pbe = Create();

            Assert.Throws<ArgumentException>(() => pbe.DecryptData(payload, "password"));
        }

        [Fact]
        public void Encrypt_InvalidArguments_Throw()
        {
            var pbe = Create();

            Assert.Throws<ArgumentException>(() => pbe.EncryptData(null, "password"));
            Assert.Throws<ArgumentException>(() => pbe.EncryptData(Utf8("data"), "  "));
            Assert.Throws<ArgumentException>(() => pbe.EncryptText("  ", "password"));
        }

        [Fact]
        public void Constructor_NullConfiguration_Throws()
            => Assert.Throws<ArgumentNullException>(() => new PasswordBasedEncryption(_encoder, null));
    }
}
