using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20;
using System;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;
using ChaCha20Poly1305 = AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20.ChaCha20Poly1305;
using CryptographicException = System.Security.Cryptography.CryptographicException;

namespace AleCGN.Security.Cryptography.Tests.Encryption
{
    public class ChaCha20Poly1305Tests
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private static readonly SymmetricKeyHelper _keyHelper = new SymmetricKeyHelper(_encoder);

        [Fact]
        public void EncryptDecrypt_DataAndText_Roundtrip()
        {
            using (var chacha = new ChaCha20Poly1305(_encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                var data = Utf8("sensitive data");
                var encryptedData = chacha.EncryptData(data);

                Assert.Equal(data, chacha.DecryptData(encryptedData));
                // self-describing envelope: header(7) + 3 field prefixes(12) + nonce(12) + tag(16) + ciphertext
                Assert.Equal(data.Length + 47, encryptedData.Length);

                var encryptedText = chacha.EncryptText("sensitive text");

                Assert.StartsWith("$chacha20-poly1305$v=1$", encryptedText);
                Assert.Equal("sensitive text", chacha.DecryptText(encryptedText));
            }
        }

        [Fact]
        public void AssociatedData_Roundtrip_AndWrongAadFails()
        {
            using (var chacha = new ChaCha20Poly1305(_encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                var payload = chacha.EncryptData(Utf8("payload"), Utf8("ctx"));

                Assert.Equal(Utf8("payload"), chacha.DecryptData(payload, Utf8("ctx")));
                Assert.ThrowsAny<Exception>(() => chacha.DecryptData(payload, Utf8("other")));
            }
        }

        [Fact]
        public void TamperedPayload_FailsAuthentication()
        {
            using (var chacha = new ChaCha20Poly1305(_encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                var payload = chacha.EncryptData(Utf8("payload data"));

                payload[0] ^= 0xFF;

                Assert.ThrowsAny<Exception>(() => chacha.DecryptData(payload));
            }
        }

        [Fact]
        public void Encrypt_SamePlaintextTwice_ProducesDifferentCiphertexts()
        {
            using (var chacha = new ChaCha20Poly1305(_encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                Assert.NotEqual(chacha.EncryptText("same"), chacha.EncryptText("same"));
            }
        }

        [Fact]
        public void SetOrUpdateKey_SwitchesKey()
        {
            using (var chacha = new ChaCha20Poly1305(_encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                var oldPayload = chacha.EncryptData(Utf8("data"));

                chacha.SetOrUpdateKey(_keyHelper.GenerateSecureRandom256BitKey());

                Assert.Equal(Utf8("data"), chacha.DecryptData(chacha.EncryptData(Utf8("data"))));
                Assert.ThrowsAny<Exception>(() => chacha.DecryptData(oldPayload));
            }
        }

        [Theory]
        [InlineData(16)]
        [InlineData(31)]
        [InlineData(33)]
        public void WrongKeySize_Throws(int keyLength)
            => Assert.Throws<ArgumentException>(() => new ChaCha20Poly1305(_encoder, new byte[keyLength]));

        [Fact]
        public void OperatingWithoutKey_Throws()
        {
            using (var chacha = new ChaCha20Poly1305(_encoder))
            {
                Assert.Throws<CryptographicException>(() => chacha.EncryptData(Utf8("data")));
            }
        }

        [Fact]
        public void DefensiveKeyCopy_CallerMutationDoesNotAffectInstance()
        {
            var key = _keyHelper.GenerateSecureRandom256BitKey();

            using (var chacha = new ChaCha20Poly1305(_encoder, key))
            {
                var payload = chacha.EncryptData(Utf8("data"));

                key[0] ^= 0xFF;

                Assert.Equal(Utf8("data"), chacha.DecryptData(payload));
            }
        }
    }
}
