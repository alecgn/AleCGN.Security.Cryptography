using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encoders
{
    public class Base64Encoder : IEncoder
    {
        private const int _base64ChunkSize = 4;

        public string Encode(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            return Convert.ToBase64String(data);
        }

        public string Encode(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            return Encode(text.ToUTF8Bytes());
        }

        public byte[] Decode(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(base64String));
            }

            if (base64String.Length % _base64ChunkSize != 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_InvalidBase64String, nameof(base64String));
            }

            try
            {
                return Convert.FromBase64String(base64String);
            }
            catch (FormatException)
            {
                throw CreateFormattedArgumentException(LibraryResources.Validation_InvalidBase64String, nameof(base64String));
            }
        }
    }
}
