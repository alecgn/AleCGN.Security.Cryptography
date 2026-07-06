using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System.Text;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encoders
{
    /// <summary>
    /// Base32 (RFC 4648): commonly used for TOTP/2FA secrets and case-insensitive identifiers.
    /// Encoding emits uppercase padded output; decoding accepts lowercase and missing padding.
    /// </summary>
    public class Base32Encoder : IEncoder
    {
        private const string _base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private const int _bitsPerChar = 5;
        private const int _bitsPerByte = 8;
        private const int _paddedGroupSize = 8;
        private const char _paddingChar = '=';

        public string Encode(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            var stringBuilder = new StringBuilder((data.Length * _bitsPerByte / _bitsPerChar) + _paddedGroupSize);
            var bitBuffer = 0;
            var bitCount = 0;

            foreach (var currentByte in data)
            {
                bitBuffer = (bitBuffer << _bitsPerByte) | currentByte;
                bitCount += _bitsPerByte;

                while (bitCount >= _bitsPerChar)
                {
                    bitCount -= _bitsPerChar;

                    stringBuilder.Append(_base32Alphabet[(bitBuffer >> bitCount) & 0x1F]);
                }
            }

            if (bitCount > 0)
            {
                stringBuilder.Append(_base32Alphabet[(bitBuffer << (_bitsPerChar - bitCount)) & 0x1F]);
            }

            while (stringBuilder.Length % _paddedGroupSize != 0)
            {
                stringBuilder.Append(_paddingChar);
            }

            return stringBuilder.ToString();
        }

        public string Encode(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            return Encode(text.ToUTF8Bytes());
        }

        public byte[] Decode(string base32String)
        {
            if (string.IsNullOrWhiteSpace(base32String))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(base32String));
            }

            var trimmedString = base32String.TrimEnd(_paddingChar);

            if (trimmedString.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_InvalidBase32String, nameof(base32String));
            }

            var data = new byte[trimmedString.Length * _bitsPerChar / _bitsPerByte];
            var bitBuffer = 0;
            var bitCount = 0;
            var index = 0;

            foreach (var currentChar in trimmedString)
            {
                var charValue = GetBase32CharValue(currentChar);

                if (charValue < 0)
                {
                    ThrowFormattedArgumentException(LibraryResources.Validation_InvalidBase32String, nameof(base32String));
                }

                bitBuffer = (bitBuffer << _bitsPerChar) | charValue;
                bitCount += _bitsPerChar;

                if (bitCount >= _bitsPerByte)
                {
                    bitCount -= _bitsPerByte;

                    data[index] = (byte)((bitBuffer >> bitCount) & 0xFF);
                    index++;
                }
            }

            return data;
        }

        private static int GetBase32CharValue(char base32Char)
        {
            if (base32Char >= 'A' && base32Char <= 'Z')
            {
                return base32Char - 'A';
            }

            if (base32Char >= 'a' && base32Char <= 'z')
            {
                return base32Char - 'a';
            }

            if (base32Char >= '2' && base32Char <= '7')
            {
                return base32Char - '2' + 26;
            }

            return -1;
        }
    }
}
