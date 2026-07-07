using AleCGN.Security.Cryptography.Encoders;
using System;
using System.Linq;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encoders
{
    public class Base64EncoderTests
    {
        private readonly Base64Encoder _encoder = new Base64Encoder();

        [Fact]
        public void Encode_KnownValue()
            => Assert.Equal("QWxlQ0dO", _encoder.Encode("AleCGN"));

        [Fact]
        public void Decode_KnownValue()
            => Assert.Equal(Utf8("AleCGN"), _encoder.Decode("QWxlQ0dO"));

        [Fact]
        public void EncodeDecode_Roundtrip()
        {
            var data = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

            Assert.Equal(data, _encoder.Decode(_encoder.Encode(data)));
        }

        [Theory]
        [InlineData("invalid length")]
        [InlineData("QWxlQ0dO!===")]
        [InlineData("ab")]
        public void Decode_InvalidString_Throws(string invalid)
            => Assert.Throws<ArgumentException>(() => _encoder.Decode(invalid));

        [Fact]
        public void Encode_NullOrEmptyData_Throws()
        {
            Assert.Throws<ArgumentException>(() => _encoder.Encode((byte[])null));
            Assert.Throws<ArgumentException>(() => _encoder.Encode(Array.Empty<byte>()));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void Decode_NullOrWhitespace_Throws(string invalid)
            => Assert.Throws<ArgumentException>(() => _encoder.Decode(invalid));
    }
}
