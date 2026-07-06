using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.KeyDerivation;
using System;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.KeyDerivation
{
    public class Argon2idTests
    {
        private static readonly HexadecimalEncoder _hexEncoder = new HexadecimalEncoder();

        // Small memory to keep tests fast; still exercises the full algorithm.
        private static readonly Argon2idConfiguration _fastConfiguration =
            new Argon2idConfiguration(memorySizeInKB: 1024, iterations: 1, parallelism: 1, saltSize: 16, derivedKeySize: 32);

        [Fact]
        public void DeriveKey_IsDeterministicForSameInputs()
        {
            var argon2 = new Argon2id(_hexEncoder, _fastConfiguration);
            var salt = _hexEncoder.Decode("000102030405060708090A0B0C0D0E0F");

            Assert.Equal(
                _hexEncoder.Encode(argon2.DeriveKey(Utf8("password"), salt)),
                _hexEncoder.Encode(argon2.DeriveKey(Utf8("password"), salt)));
        }

        [Fact]
        public void DeriveKey_DifferentPasswordOrSalt_ProducesDifferentKeys()
        {
            var argon2 = new Argon2id(_hexEncoder, _fastConfiguration);
            var salt1 = _hexEncoder.Decode("000102030405060708090A0B0C0D0E0F");
            var salt2 = _hexEncoder.Decode("FF0102030405060708090A0B0C0D0E0F");
            var baseline = _hexEncoder.Encode(argon2.DeriveKey(Utf8("password"), salt1));

            Assert.NotEqual(baseline, _hexEncoder.Encode(argon2.DeriveKey(Utf8("Password"), salt1)));
            Assert.NotEqual(baseline, _hexEncoder.Encode(argon2.DeriveKey(Utf8("password"), salt2)));
        }

        [Fact]
        public void DeriveKey_ParametersAffectOutput()
        {
            var salt = _hexEncoder.Decode("000102030405060708090A0B0C0D0E0F");
            var lowMemory = new Argon2id(_hexEncoder, new Argon2idConfiguration(1024, 1, 1, 16, 32));
            var highMemory = new Argon2id(_hexEncoder, new Argon2idConfiguration(2048, 1, 1, 16, 32));
            var moreIterations = new Argon2id(_hexEncoder, new Argon2idConfiguration(1024, 2, 1, 16, 32));

            var baseline = _hexEncoder.Encode(lowMemory.DeriveKey(Utf8("password"), salt));

            Assert.NotEqual(baseline, _hexEncoder.Encode(highMemory.DeriveKey(Utf8("password"), salt)));
            Assert.NotEqual(baseline, _hexEncoder.Encode(moreIterations.DeriveKey(Utf8("password"), salt)));
        }

        [Fact]
        public void GeneratedSalt_HasConfiguredSize_AndVerifies()
        {
            var argon2 = new Argon2id(_hexEncoder, _fastConfiguration);
            var key = argon2.DeriveKey(Utf8("password"), out var salt);

            Assert.Equal(16, salt.Length);
            Assert.Equal(32, key.Length);
            Assert.True(argon2.VerifyKey(Utf8("password"), salt, key));
            Assert.False(argon2.VerifyKey(Utf8("wrong"), salt, key));
        }

        [Fact]
        public void DeriveTextKey_Roundtrip()
        {
            var argon2 = new Argon2id(_hexEncoder, _fastConfiguration);
            var encodedKey = argon2.DeriveTextKey("password", out var encodedSalt);

            Assert.True(argon2.VerifyTextKey("password", encodedSalt, encodedKey));
            Assert.False(argon2.VerifyTextKey("wrong", encodedSalt, encodedKey));
        }

        [Theory]
        [InlineData(0, 1, 1, 16, 32)]   // memory <= 0
        [InlineData(1024, 0, 1, 16, 32)] // iterations <= 0
        [InlineData(1024, 1, 0, 16, 32)] // parallelism <= 0
        [InlineData(1024, 1, 1, 4, 32)]  // salt below minimum
        [InlineData(1024, 1, 1, 16, 0)]  // derived key size <= 0
        public void Configuration_InvalidValues_Throw(int memory, int iterations, int parallelism, int saltSize, int keySize)
            => Assert.Throws<ArgumentException>(() =>
                new Argon2idConfiguration(memory, iterations, parallelism, saltSize, keySize));

        [Fact]
        public void Constructor_NullConfiguration_Throws()
            => Assert.Throws<ArgumentNullException>(() => new Argon2id(_hexEncoder, null));
    }
}
