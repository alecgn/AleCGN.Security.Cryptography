using AleCGN.Security.Cryptography.Encoders;
using System;
using System.Linq;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encoders
{
    public class HexadecimalEncoderTests
    {
        private readonly HexadecimalEncoder _encoder = new HexadecimalEncoder();

        [Fact]
        public void Encode_KnownValue()
            => Assert.Equal("616263", _encoder.Encode("abc"));

        [Fact]
        public void Encode_AllByteValues()
        {
            var data = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            var encoded = _encoder.Encode(data);

            Assert.Equal(512, encoded.Length);
            Assert.StartsWith("000102", encoded);
            Assert.EndsWith("FDFEFF", encoded);
        }

        [Theory]
        [InlineData("616263")]
        [InlineData("0x616263")]
        [InlineData("0X616263")]
        [InlineData("abcdef")] // lowercase hex digits
        public void Decode_AcceptsPrefixAndCase(string input)
            => Assert.NotEmpty(_encoder.Decode(input));

        [Fact]
        public void Decode_Roundtrip()
        {
            var data = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

            Assert.Equal(data, _encoder.Decode(_encoder.Encode(data)));
        }

        [Fact]
        public void Decode_LowercaseAndUppercase_SameResult()
            => Assert.Equal(_encoder.Decode("deadbeef"), _encoder.Decode("DEADBEEF"));

        [Theory]
        [InlineData("ABC")]      // odd length
        [InlineData("0x")]       // prefix only
        [InlineData("GG")]       // invalid chars
        [InlineData("12 4")]     // whitespace inside
        public void Decode_InvalidString_Throws(string invalid)
            => Assert.Throws<ArgumentException>(() => _encoder.Decode(invalid));

        [Fact]
        public void Encode_NullOrEmpty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _encoder.Encode((byte[])null));
            Assert.Throws<ArgumentException>(() => _encoder.Encode(Array.Empty<byte>()));
        }
    }
}
