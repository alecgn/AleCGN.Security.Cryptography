using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encoders
{
    /// <summary>
    /// URL-safe base64 (RFC 4648 section 5): '+' and '/' are replaced by '-' and '_' and padding is omitted,
    /// producing strings safe for URLs, file names and tokens.
    /// </summary>
    public class Base64UrlEncoder : IEncoder
    {
        private const int _base64ChunkSize = 4;

        public string Encode(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        public string Encode(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            return Encode(text.ToUTF8Bytes());
        }

        public byte[] Decode(string base64UrlString)
        {
            if (string.IsNullOrWhiteSpace(base64UrlString))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(base64UrlString));
            }

            var base64String = base64UrlString
                .Replace('-', '+')
                .Replace('_', '/');

            var paddingLength = (_base64ChunkSize - (base64String.Length % _base64ChunkSize)) % _base64ChunkSize;

            if (paddingLength == 3)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_InvalidBase64String, nameof(base64UrlString));
            }

            try
            {
                return Convert.FromBase64String(base64String + new string('=', paddingLength));
            }
            catch (FormatException)
            {
                throw CreateFormattedArgumentException(LibraryResources.Validation_InvalidBase64String, nameof(base64UrlString));
            }
        }
    }
}
