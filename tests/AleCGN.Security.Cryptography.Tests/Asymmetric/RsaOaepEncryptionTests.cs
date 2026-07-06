using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Rsa;
using System;
using System.Security.Cryptography;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Asymmetric
{
    public class RsaOaepEncryptionTests
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private static readonly AsymmetricKeyPair _keyPair = new RsaKeyPairHelper().GenerateKeyPair();

        [Fact]
        public void KeyPair_IsPemEncoded()
        {
            Assert.Contains("BEGIN PUBLIC KEY", _keyPair.PublicKeyPem);
            Assert.Contains("PRIVATE KEY", _keyPair.PrivateKeyPem);
        }

        [Fact]
        public void EncryptDecrypt_DataAndText_Roundtrip()
        {
            var rsa = new RsaOaepEncryption(_encoder, _keyPair.PublicKeyPem, _keyPair.PrivateKeyPem);
            var data = Utf8("an AES key, for example");

            Assert.Equal(data, rsa.DecryptData(rsa.EncryptData(data)));
            Assert.Equal("small secret", rsa.DecryptText(rsa.EncryptText("small secret")));
        }

        [Fact]
        public void Encrypt_SamePlaintextTwice_ProducesDifferentCiphertexts()
        {
            var rsa = new RsaOaepEncryption(_encoder, _keyPair.PublicKeyPem);

            Assert.NotEqual(rsa.EncryptText("same"), rsa.EncryptText("same")); // OAEP is randomized
        }

        [Fact]
        public void PrivateKeyPem_SatisfiesPublicKeyParameter()
        {
            // The public half is extracted from a private-key PEM
            var rsa = new RsaOaepEncryption(_encoder, publicKeyPem: _keyPair.PrivateKeyPem, privateKeyPem: _keyPair.PrivateKeyPem);

            Assert.Equal("secret", rsa.DecryptText(rsa.EncryptText("secret")));
        }

        [Fact]
        public void Decrypt_WithWrongKey_Fails()
        {
            var otherKeyPair = new RsaKeyPairHelper().GenerateKeyPair();
            var encryptor = new RsaOaepEncryption(_encoder, _keyPair.PublicKeyPem);
            var wrongDecryptor = new RsaOaepEncryption(_encoder, privateKeyPem: otherKeyPair.PrivateKeyPem);

            Assert.ThrowsAny<Exception>(() => wrongDecryptor.DecryptText(encryptor.EncryptText("secret")));
        }

        [Fact]
        public void Encrypt_WithoutPublicKey_Throws()
        {
            var rsa = new RsaOaepEncryption(_encoder);

            Assert.Throws<CryptographicException>(() => rsa.EncryptText("secret"));
        }

        [Fact]
        public void Decrypt_WithoutPrivateKey_Throws()
        {
            var rsa = new RsaOaepEncryption(_encoder, _keyPair.PublicKeyPem);

            Assert.Throws<CryptographicException>(() => rsa.DecryptText(rsa.EncryptText("secret")));
        }

        [Fact]
        public void Constructor_InvalidPem_Throws()
            => Assert.Throws<ArgumentException>(() => new RsaOaepEncryption(_encoder, publicKeyPem: "not a pem"));

        [Fact]
        public void GenerateKeyPair_RespectsKeySize()
        {
            // 2048-bit RSA-OAEP-SHA256 fits at most 190 bytes of plaintext
            var rsa = new RsaOaepEncryption(_encoder, _keyPair.PublicKeyPem, _keyPair.PrivateKeyPem);
            var maxPayload = RepeatedBytes(0x42, 190);

            Assert.Equal(maxPayload, rsa.DecryptData(rsa.EncryptData(maxPayload)));
            Assert.ThrowsAny<Exception>(() => rsa.EncryptData(RepeatedBytes(0x42, 191)));
        }
    }
}
