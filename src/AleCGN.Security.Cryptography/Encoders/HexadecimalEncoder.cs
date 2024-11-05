using AleCGN.Security.Cryptography.Resources;
using System;
using System.Collections.Generic;
using System.Linq;
//using System.Text;
using System.Text.RegularExpressions;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encoders
{
    public class HexadecimalEncoder : IEncoder
    {
        private const int _hexadecimalChunkSize = 2;
        private const int _hexadecimalBase = 16;
        private const string _hexadecimalPrefix = "0x";
        private const int _hexadecimalPrefixLength = 2;
        private static readonly Regex _regexHexadecimalString = new Regex(LibraryResources.RegularExpression_HexadecimalString);

        public string Encode(byte[] data)
        {
            if (data == null || data.Length <= 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            //var stringBuilder = new StringBuilder();

            //for (int i = 0; i < data.Length; i++)
            //{
            //    stringBuilder.Append(data[i].ToString("X2"));
            //}

            //return stringBuilder.ToString();

            return string.Concat(data.Select(b => b.ToString("X2")));
        }

        public byte[] Decode(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hexadecimalString));
            }

            CheckValidEncodedString(hexadecimalString);

            if (hexadecimalString.StartsWith(_hexadecimalPrefix, StringComparison.OrdinalIgnoreCase))
            {
                hexadecimalString = hexadecimalString.Substring(_hexadecimalPrefixLength);
            }

            var data = new byte[hexadecimalString.Length / _hexadecimalChunkSize];
            var index = 0;

            foreach (var hexVal in ChunkHexadecimalString(hexadecimalString))
            {
                data[index] = Convert.ToByte(hexVal, _hexadecimalBase);
                index++;
            }

            return data;
        }

        private IEnumerable<string> ChunkHexadecimalString(string hexadecimalString)
        {
            for (var index = 0; index < hexadecimalString.Length; index += _hexadecimalChunkSize)
            {
                yield return hexadecimalString.Substring(index, _hexadecimalChunkSize);
            }
        }

        private void CheckValidEncodedString(string hexadecimalString)
        {
            if (hexadecimalString.Length % _hexadecimalChunkSize != 0 && !_regexHexadecimalString.IsMatch(hexadecimalString))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_InvalidHexadecimalString, nameof(hexadecimalString));
            }
        }
    }
}
