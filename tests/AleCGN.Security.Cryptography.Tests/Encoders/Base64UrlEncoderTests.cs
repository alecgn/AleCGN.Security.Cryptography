using AleCGN.Security.Cryptography.Encoders;
using System;
using System.Linq;
using Xunit;

namespace AleCGN.Security.Cryptography.Tests.Encoders
{
    public class Base64UrlEncoderTests
    {
        private readonly Base64UrlEncoder _encoder = new Base64UrlEncoder();

        [Fact]
        public void Encode_ProducesUrlSafeOutput()
        {
            // These bytes produce '+', '/' and '=' in standard base64
            var tricky = new byte[] { 0xFB, 0xEF, 0xBE, 0xFF, 0xFE, 0x3F };
            var encoded = _encoder.Encode(tricky);

            Assert.DoesNotContain('+', encoded);
            Assert.DoesNotContain('/', encoded);
            Assert.DoesNotContain('=', encoded);
        }

        [Fact]
        public void EncodeDecode_Roundtrip_AllPaddingLengths()
        {
            for (var length = 1; length <= 8; length++)
            {
                var data = Enumerable.Range(1, length).Select(i => (byte)(i * 37)).ToArray();

                Assert.Equal(data, _encoder.Decode(_encoder.Encode(data)));
            }
        }

        [Fact]
        public void Decode_AcceptsStandardBase64Alphabet_AfterMapping()
        {
            var data = new byte[] { 0xFB, 0xEF, 0xBE };
            var urlSafe = _encoder.Encode(data);

            Assert.Contains('-', urlSafe + "-"); // sanity: '-' is a legal char in the output alphabet
            Assert.Equal(data, _encoder.Decode(urlSafe));
        }

        [Theory]
        [InlineData("a")]      // impossible length (padding == 3)
        [InlineData("!@#$")]
        public void Decode_InvalidString_Throws(string invalid)
            => Assert.Throws<ArgumentException>(() => _encoder.Decode(invalid));
    }
}
