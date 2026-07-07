using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using System;
using System.Security.Cryptography;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encryption
{
    public class AesGcmTests
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private static readonly SymmetricKeyHelper _keyHelper = new SymmetricKeyHelper(_encoder);

        private static IAesGcmBase Create(int keySizeBits, byte[] key = null)
        {
            switch (keySizeBits)
            {
                case 128: return key is null ? new AesGcm128(_encoder) : new AesGcm128(_encoder, key);
                case 192: return key is null ? new AesGcm192(_encoder) : new AesGcm192(_encoder, key);
                case 256: return key is null ? new AesGcm256(_encoder) : new AesGcm256(_encoder, key);
                default: throw new ArgumentOutOfRangeException(nameof(keySizeBits));
            }
        }

        private static byte[] GenerateKey(int keySizeBits)
        {
            switch (keySizeBits)
            {
                case 128: return _keyHelper.GenerateSecureRandom128BitKey();
                case 192: return _keyHelper.GenerateSecureRandom192BitKey();
                case 256: return _keyHelper.GenerateSecureRandom256BitKey();
                default: throw new ArgumentOutOfRangeException(nameof(keySizeBits));
            }
        }

        [Theory]
        [InlineData(128)]
        [InlineData(192)]
        [InlineData(256)]
        public void EncryptDecrypt_Data_Roundtrip(int keySizeBits)
        {
            using (var aes = Create(keySizeBits, GenerateKey(keySizeBits)))
            {
                var data = Utf8("sensitive data");
                var encrypted = aes.EncryptData(data);

                Assert.Equal(data, aes.DecryptData(encrypted));
                // self-describing envelope: header(7) + 3 field prefixes(12) + nonce(12) + tag(16) + ciphertext
                Assert.Equal(data.Length + 47, encrypted.Length);
                Assert.Equal((byte)'A', encrypted[0]); // "ACGN" magic
            }
        }

        [Theory]
        [InlineData(128, "$aes128-gcm$v=1$")]
        [InlineData(192, "$aes192-gcm$v=1$")]
        [InlineData(256, "$aes256-gcm$v=1$")]
        public void EncryptDecrypt_Text_Roundtrip_SelfDescribingFormat(int keySizeBits, string expectedPrefix)
        {
            using (var aes = Create(keySizeBits, GenerateKey(keySizeBits)))
            {
                var encrypted = aes.EncryptText("sensitive text");

                // $<algorithm>$v=1$<nonce>$<tag>$<ciphertext> — 6 '$'-separated parts
                Assert.StartsWith(expectedPrefix, encrypted);
                Assert.Equal(6, encrypted.Split('$').Length);
                Assert.Equal("sensitive text", aes.DecryptText(encrypted));
            }
        }

        [Fact]
        public void DecryptText_WrongAlgorithmEnvelope_Throws()
        {
            using (var aes128 = Create(128, GenerateKey(128)))
            using (var aes256 = Create(256, GenerateKey(256)))
            {
                var payload = aes128.EncryptText("data");

                // A payload produced by another algorithm is rejected by format, not by garbled output
                Assert.Throws<ArgumentException>(() => aes256.DecryptText(payload));
            }
        }

        [Fact]
        public void Encrypt_SamePlaintextTwice_ProducesDifferentCiphertexts()
        {
            using (var aes = Create(256, GenerateKey(256)))
            {
                Assert.NotEqual(aes.EncryptText("same input"), aes.EncryptText("same input"));
            }
        }

        [Fact]
        public void AssociatedData_Roundtrip_AndWrongAadFails()
        {
            using (var aes = Create(256, GenerateKey(256)))
            {
                var payload = aes.EncryptData(Utf8("payload"), Utf8("user:42"));

                Assert.Equal(Utf8("payload"), aes.DecryptData(payload, Utf8("user:42")));
                Assert.ThrowsAny<Exception>(() => aes.DecryptData(payload, Utf8("user:43")));
                Assert.ThrowsAny<Exception>(() => aes.DecryptData(payload)); // missing AAD
            }
        }

        [Theory]
        [InlineData(0)]              // ciphertext
        [InlineData(-2)]             // tag region (relative to end: length - 28 + ...)
        public void TamperedPayload_FailsAuthentication(int position)
        {
            using (var aes = Create(256, GenerateKey(256)))
            {
                var payload = aes.EncryptData(Utf8("payload data"));
                var index = position >= 0 ? position : payload.Length + position;

                payload[index] ^= 0xFF;

                Assert.ThrowsAny<Exception>(() => aes.DecryptData(payload));
            }
        }

        [Fact]
        public void Decrypt_WithWrongKey_Fails()
        {
            var payload = default(byte[]);

            using (var aes1 = Create(256, GenerateKey(256)))
            {
                payload = aes1.EncryptData(Utf8("data"));
            }

            using (var aes2 = Create(256, GenerateKey(256)))
            {
                Assert.ThrowsAny<Exception>(() => aes2.DecryptData(payload));
            }
        }

        [Fact]
        public void SetOrUpdateKey_SwitchesKey()
        {
            var key1 = GenerateKey(256);
            var key2 = GenerateKey(256);

            using (var aes = Create(256, key1))
            {
                var withKey1 = aes.EncryptData(Utf8("data"));

                aes.SetOrUpdateKey(key2);

                var withKey2 = aes.EncryptData(Utf8("data"));

                Assert.Equal(Utf8("data"), aes.DecryptData(withKey2));
                Assert.ThrowsAny<Exception>(() => aes.DecryptData(withKey1)); // old key gone
            }
        }

        [Fact]
        public void EncodedKeyConstructor_EquivalentToRawKey()
        {
            var key = GenerateKey(256);

            using (var fromRaw = new AesGcm256(_encoder, key))
            using (var fromEncoded = new AesGcm256(_encoder, _encoder.Encode(key)))
            {
                Assert.Equal(Utf8("data"), fromEncoded.DecryptData(fromRaw.EncryptData(Utf8("data"))));
            }
        }

        [Fact]
        public void DefensiveKeyCopy_CallerMutationDoesNotAffectInstance()
        {
            var key = GenerateKey(256);

            using (var aes = new AesGcm256(_encoder, key))
            {
                var payload = aes.EncryptData(Utf8("data"));

                key[0] ^= 0xFF; // mutate the caller's array

                Assert.Equal(Utf8("data"), aes.DecryptData(payload));
            }
        }

        [Theory]
        [InlineData(128, 24)]
        [InlineData(192, 16)]
        [InlineData(256, 16)]
        public void WrongKeySize_Throws(int keySizeBits, int wrongKeyLength)
            => Assert.Throws<ArgumentException>(() => Create(keySizeBits, new byte[wrongKeyLength]));

        [Fact]
        public void OperatingWithoutKey_Throws()
        {
            using (var aes = Create(256))
            {
                Assert.Throws<CryptographicException>(() => aes.EncryptData(Utf8("data")));
            }
        }

        [Fact]
        public void Decrypt_PayloadTooShort_Throws()
        {
            using (var aes = Create(256, GenerateKey(256)))
            {
                Assert.Throws<ArgumentException>(() => aes.DecryptData(new byte[28])); // no room for ciphertext
            }
        }
    }
}
