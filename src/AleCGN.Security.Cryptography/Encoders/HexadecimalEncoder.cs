using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encoders
{
    public class HexadecimalEncoder : IEncoder
    {
        private const int _hexadecimalChunkSize = 2;
        private const string _hexadecimalPrefix = "0x";
        private const int _hexadecimalPrefixLength = 2;
        private const string _hexadecimalChars = "0123456789ABCDEF";

        public string Encode(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            var encodedChars = new char[data.Length * _hexadecimalChunkSize];

            for (var index = 0; index < data.Length; index++)
            {
                var currentByte = data[index];

                encodedChars[index * _hexadecimalChunkSize] = _hexadecimalChars[currentByte >> 4];
                encodedChars[(index * _hexadecimalChunkSize) + 1] = _hexadecimalChars[currentByte & 0xF];
            }

            return new string(encodedChars);
        }

        public string Encode(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            return Encode(text.ToUTF8Bytes());
        }

        public byte[] Decode(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hexadecimalString));
            }

            var startIndex = (hexadecimalString.StartsWith(_hexadecimalPrefix, StringComparison.OrdinalIgnoreCase)
                ? _hexadecimalPrefixLength
                : 0);
            var hexadecimalDigitsCount = hexadecimalString.Length - startIndex;

            if (hexadecimalDigitsCount == 0 || hexadecimalDigitsCount % _hexadecimalChunkSize != 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_InvalidHexadecimalString, nameof(hexadecimalString));
            }

            var data = new byte[hexadecimalDigitsCount / _hexadecimalChunkSize];

            for (var index = 0; index < data.Length; index++)
            {
                var highNibble = GetHexadecimalCharValue(hexadecimalString[startIndex + (index * _hexadecimalChunkSize)]);
                var lowNibble = GetHexadecimalCharValue(hexadecimalString[startIndex + (index * _hexadecimalChunkSize) + 1]);

                if (highNibble < 0 || lowNibble < 0)
                {
                    ThrowFormattedArgumentException(LibraryResources.Validation_InvalidHexadecimalString, nameof(hexadecimalString));
                }

                data[index] = (byte)((highNibble << 4) | lowNibble);
            }

            return data;
        }

        private static int GetHexadecimalCharValue(char hexadecimalChar)
        {
            if (hexadecimalChar >= '0' && hexadecimalChar <= '9')
            {
                return hexadecimalChar - '0';
            }

            if (hexadecimalChar >= 'A' && hexadecimalChar <= 'F')
            {
                return hexadecimalChar - 'A' + 10;
            }

            if (hexadecimalChar >= 'a' && hexadecimalChar <= 'f')
            {
                return hexadecimalChar - 'a' + 10;
            }

            return -1;
        }
    }
}
