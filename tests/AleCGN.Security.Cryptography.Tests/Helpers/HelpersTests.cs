using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Helpers;
using System.Linq;
using Xunit;

namespace AleCGN.Security.Cryptography.Tests.Helpers
{
    public class HelpersTests
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private readonly SymmetricKeyHelper _keyHelper = new SymmetricKeyHelper(_encoder);

        [Fact]
        public void SymmetricKeyHelper_GeneratesKeysWithCorrectSizes()
        {
            Assert.Equal(16, _keyHelper.GenerateSecureRandom128BitKey().Length);
            Assert.Equal(24, _keyHelper.GenerateSecureRandom192BitKey().Length);
            Assert.Equal(32, _keyHelper.GenerateSecureRandom256BitKey().Length);
        }

        [Fact]
        public void SymmetricKeyHelper_EncodedKeys_DecodeToCorrectSizes()
        {
            Assert.Equal(16, _encoder.Decode(_keyHelper.GenerateSecureRandom128BitEncodedKey()).Length);
            Assert.Equal(24, _encoder.Decode(_keyHelper.GenerateSecureRandom192BitEncodedKey()).Length);
            Assert.Equal(32, _encoder.Decode(_keyHelper.GenerateSecureRandom256BitEncodedKey()).Length);
        }

        [Fact]
        public void GenerateSecureRandomBytes_ProducesRequestedLength_AndVaries()
        {
            var bytes1 = CryptographyHelper.GenerateSecureRandomBytes(32);
            var bytes2 = CryptographyHelper.GenerateSecureRandomBytes(32);

            Assert.Equal(32, bytes1.Length);
            Assert.False(bytes1.SequenceEqual(bytes2)); // 2^-256 false-negative probability
        }

        [Fact]
        public void FixedTimeEquals_Semantics()
        {
            var left = new byte[] { 1, 2, 3, 4 };

            Assert.True(CryptographyHelper.FixedTimeEquals(left, new byte[] { 1, 2, 3, 4 }));
            Assert.False(CryptographyHelper.FixedTimeEquals(left, new byte[] { 1, 2, 3, 5 }));
            Assert.False(CryptographyHelper.FixedTimeEquals(left, new byte[] { 1, 2, 3 }));   // length mismatch
            Assert.False(CryptographyHelper.FixedTimeEquals(left, null));
            Assert.False(CryptographyHelper.FixedTimeEquals(null, left));
        }
    }
}
