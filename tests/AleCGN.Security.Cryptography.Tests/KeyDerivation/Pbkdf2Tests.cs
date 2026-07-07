using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.KeyDerivation;
using System;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.KeyDerivation
{
    public class Pbkdf2Tests
    {
        private static readonly HexadecimalEncoder _hexEncoder = new HexadecimalEncoder();

        private static Pbkdf2 Create(Pbkdf2PseudoRandomFunction prf, int iterations, int derivedKeySize)
            => new Pbkdf2(_hexEncoder, new Pbkdf2Configuration(prf, iterations, saltSize: 16, derivedKeySize: derivedKeySize));

        // RFC 6070 test vectors (PBKDF2-HMAC-SHA1, P="password", S="salt")
        [Theory]
        [InlineData(1, "0C60C80F961F0E71F3A9B524AF6012062FE037A6")]
        [InlineData(2, "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957")]
        [InlineData(4096, "4B007901B765489ABEAD49D926F721D065A429C1")]
        public void DeriveKey_Rfc6070Vectors(int iterations, string expected)
        {
            var pbkdf2 = Create(Pbkdf2PseudoRandomFunction.HMACSHA1, iterations, 20);

            Assert.Equal(expected, _hexEncoder.Encode(pbkdf2.DeriveKey(Utf8("password"), Utf8("salt"))));
        }

        [Fact]
        public void DeriveKey_Sha256KnownVector()
        {
            var pbkdf2 = Create(Pbkdf2PseudoRandomFunction.HMACSHA256, 1, 32);

            Assert.Equal(
                "120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B",
                _hexEncoder.Encode(pbkdf2.DeriveKey(Utf8("password"), Utf8("salt"))));
        }

        [Fact]
        public void DeriveKey_GeneratedSalt_HasConfiguredSizeAndVerifies()
        {
            var pbkdf2 = new Pbkdf2(_hexEncoder, new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 1_000, saltSize: 24, derivedKeySize: 32));
            var key = pbkdf2.DeriveKey(Utf8("password"), out var salt);

            Assert.Equal(24, salt.Length);
            Assert.Equal(32, key.Length);
            Assert.True(pbkdf2.VerifyKey(Utf8("password"), salt, key));
            Assert.False(pbkdf2.VerifyKey(Utf8("wrong"), salt, key));
        }

        [Fact]
        public void DeriveTextKey_RoundtripsThroughEncoder()
        {
            var pbkdf2 = Create(Pbkdf2PseudoRandomFunction.HMACSHA256, 1_000, 32);
            var encodedKey = pbkdf2.DeriveTextKey("password", out var encodedSalt);

            Assert.True(pbkdf2.VerifyTextKey("password", encodedSalt, encodedKey));
            Assert.False(pbkdf2.VerifyTextKey("wrong", encodedSalt, encodedKey));
        }

        [Fact]
        public void DifferentSalts_ProduceDifferentKeys()
        {
            var pbkdf2 = Create(Pbkdf2PseudoRandomFunction.HMACSHA256, 1_000, 32);

            var key1 = pbkdf2.DeriveKey(Utf8("password"), out _);
            var key2 = pbkdf2.DeriveKey(Utf8("password"), out _);

            Assert.NotEqual(_hexEncoder.Encode(key1), _hexEncoder.Encode(key2));
        }

        [Theory]
        [InlineData(0, 16, 32)]    // iterations <= 0
        [InlineData(-1, 16, 32)]
        [InlineData(1000, 4, 32)]  // salt < RFC 8018 minimum (8)
        [InlineData(1000, 16, 0)]  // derived key size <= 0
        public void Configuration_InvalidValues_Throw(int iterations, int saltSize, int derivedKeySize)
            => Assert.Throws<ArgumentException>(() => new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA256, iterations, saltSize, derivedKeySize));

        [Fact]
        public void Constructor_NullConfiguration_Throws()
            => Assert.Throws<ArgumentNullException>(() => new Pbkdf2(_hexEncoder, null));

        [Fact]
        public void DeriveKey_InvalidInputs_Throw()
        {
            var pbkdf2 = Create(Pbkdf2PseudoRandomFunction.HMACSHA256, 1_000, 32);

            Assert.Throws<ArgumentException>(() => pbkdf2.DeriveKey(null, Utf8("salt")));
            Assert.Throws<ArgumentException>(() => pbkdf2.DeriveKey(Utf8("password"), Array.Empty<byte>()));
        }
    }
}
