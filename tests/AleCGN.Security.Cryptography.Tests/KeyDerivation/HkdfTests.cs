using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.KeyDerivation;
using System;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.KeyDerivation
{
    public class HkdfTests
    {
        private static readonly HexadecimalEncoder _hexEncoder = new HexadecimalEncoder();

        [Fact]
        public void DeriveKey_Rfc5869TestCase1()
        {
            var hkdf = new Hkdf(_hexEncoder); // SHA256 default
            var okm = hkdf.DeriveKey(
                inputKeyMaterial: RepeatedBytes(0x0B, 22),
                derivedKeySize: 42,
                salt: _hexEncoder.Decode("000102030405060708090a0b0c"),
                info: _hexEncoder.Decode("f0f1f2f3f4f5f6f7f8f9"));

            Assert.Equal(
                "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865",
                _hexEncoder.Encode(okm));
        }

        [Fact]
        public void DeriveKey_Rfc5869TestCase3_NoSaltNoInfo()
        {
            var hkdf = new Hkdf(_hexEncoder);
            var okm = hkdf.DeriveKey(RepeatedBytes(0x0B, 22), 42, salt: null, info: null);

            Assert.Equal(
                "8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8",
                _hexEncoder.Encode(okm));
        }

        [Fact]
        public void DeriveKey_DifferentInfo_ProducesIndependentKeys()
        {
            var hkdf = new Hkdf(_hexEncoder);
            var masterKey = RepeatedBytes(0xAA, 32);

            var encryptionKey = hkdf.DeriveKey(masterKey, 32, info: Utf8("encryption"));
            var macKey = hkdf.DeriveKey(masterKey, 32, info: Utf8("mac"));

            Assert.NotEqual(_hexEncoder.Encode(encryptionKey), _hexEncoder.Encode(macKey));
        }

        [Fact]
        public void DeriveKey_DifferentHashAlgorithms_ProduceDifferentOutput()
        {
            var masterKey = RepeatedBytes(0xAA, 32);
            var sha256 = new Hkdf(_hexEncoder, HashAlgorithmKind.SHA256).DeriveKey(masterKey, 32);
            var sha512 = new Hkdf(_hexEncoder, HashAlgorithmKind.SHA512).DeriveKey(masterKey, 32);

            Assert.NotEqual(_hexEncoder.Encode(sha256), _hexEncoder.Encode(sha512));
        }

        [Fact]
        public void DeriveTextKey_IsDeterministic()
        {
            var hkdf = new Hkdf(_hexEncoder);

            Assert.Equal(
                hkdf.DeriveTextKey("master", 32, "salt", "info"),
                hkdf.DeriveTextKey("master", 32, "salt", "info"));
        }

        [Fact]
        public void DeriveKey_InvalidInputs_Throw()
        {
            var hkdf = new Hkdf(_hexEncoder);

            Assert.Throws<ArgumentException>(() => hkdf.DeriveKey(null, 32));
            Assert.Throws<ArgumentException>(() => hkdf.DeriveKey(Array.Empty<byte>(), 32));
            Assert.Throws<ArgumentException>(() => hkdf.DeriveKey(RepeatedBytes(1, 32), 0));
        }
    }
}
