using AleCGN.Security.Cryptography.Encoders;
using System;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encoders
{
    public class Base32EncoderTests
    {
        private readonly Base32Encoder _encoder = new Base32Encoder();

        // RFC 4648 section 10 test vectors
        [Theory]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public void Encode_Rfc4648Vectors(string input, string expected)
            => Assert.Equal(expected, _encoder.Encode(input));

        [Theory]
        [InlineData("MY======", "f")]
        [InlineData("MZXW6YTBOI======", "foobar")]
        [InlineData("mzxw6ytboi======", "foobar")]   // lowercase
        [InlineData("MZXW6YTBOI", "foobar")]         // unpadded
        public void Decode_Rfc4648Vectors(string input, string expected)
            => Assert.Equal(Utf8(expected), _encoder.Decode(input));

        [Fact]
        public void EncodeDecode_Roundtrip_BinaryData()
        {
            var data = new byte[] { 0x00, 0xFF, 0x10, 0x88, 0x99, 0xAB, 0x01 };

            Assert.Equal(data, _encoder.Decode(_encoder.Encode(data)));
        }

        [Theory]
        [InlineData("MZXW1===")]   // '1' not in alphabet
        [InlineData("========")]   // padding only
        [InlineData("MZ XW")]      // whitespace inside
        public void Decode_InvalidString_Throws(string invalid)
            => Assert.Throws<ArgumentException>(() => _encoder.Decode(invalid));
    }
}
