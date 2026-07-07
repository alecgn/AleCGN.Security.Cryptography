using AleCGN.Security.Cryptography.Resources;
using System;
using System.Text;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Helpers
{
    /// <summary>
    /// Registry of the algorithm identifiers used by the self-describing payload envelopes.
    /// </summary>
    internal static class PayloadAlgorithms
    {
        internal const byte Aes128Gcm = 1;
        internal const byte Aes192Gcm = 2;
        internal const byte Aes256Gcm = 3;
        internal const byte ChaCha20Poly1305 = 4;
        internal const byte PasswordBasedAes256Gcm = 5;
        internal const byte RsaOaep = 6;
        internal const byte Dpapi = 7;
        internal const byte RsaPss = 8;
        internal const byte Ecdsa = 9;

        internal const string Aes128GcmName = "aes128-gcm";
        internal const string Aes192GcmName = "aes192-gcm";
        internal const string Aes256GcmName = "aes256-gcm";
        internal const string ChaCha20Poly1305Name = "chacha20-poly1305";
        internal const string PasswordBasedAes256GcmName = "pbe-aes256-gcm";
        internal const string DpapiName = "dpapi";
    }

    /// <summary>
    /// Canonical self-describing payload formats shared by every encryption/signature API,
    /// so no information is ever inferred from byte positions or sizes.
    ///
    /// String form (PHC-style, unpadded Base64 fields):
    ///   $&lt;algorithm&gt;$v=&lt;version&gt;$[&lt;parameters&gt;$]&lt;field1&gt;$&lt;field2&gt;...
    ///
    /// Binary form:
    ///   magic "ACGN"(4) | format version(1) | algorithm id(1) | field count(1) |
    ///   { field length (int32, little-endian) | field bytes } per field
    /// </summary>
    internal static class PayloadFormat
    {
        internal const byte FormatVersion = 1;

        private static readonly byte[] _magicBytes = { 0x41, 0x43, 0x47, 0x4E }; // "ACGN"
        private const int _headerSize = 7; // magic(4) + version(1) + algorithm id(1) + field count(1)
        private const int _fieldPrefixSize = 4;

        #region Binary form

        internal static int GetBinarySize(int[] fieldLengths)
        {
            var total = _headerSize;

            foreach (var fieldLength in fieldLengths)
            {
                total += _fieldPrefixSize + fieldLength;
            }

            return total;
        }

        /// <summary>
        /// Allocates a payload buffer with the header and field length prefixes already written,
        /// returning the offset where each field's bytes must be placed (enables zero-copy writes).
        /// </summary>
        internal static byte[] CreateBinary(byte algorithmId, int[] fieldLengths, out int[] fieldOffsets)
        {
            var payload = new byte[GetBinarySize(fieldLengths)];

            Array.Copy(_magicBytes, payload, _magicBytes.Length);

            payload[4] = FormatVersion;
            payload[5] = algorithmId;
            payload[6] = (byte)fieldLengths.Length;

            fieldOffsets = new int[fieldLengths.Length];

            var position = _headerSize;

            for (var index = 0; index < fieldLengths.Length; index++)
            {
                var fieldLength = fieldLengths[index];

                payload[position] = (byte)(fieldLength & 0xFF);
                payload[position + 1] = (byte)((fieldLength >> 8) & 0xFF);
                payload[position + 2] = (byte)((fieldLength >> 16) & 0xFF);
                payload[position + 3] = (byte)((fieldLength >> 24) & 0xFF);

                fieldOffsets[index] = position + _fieldPrefixSize;
                position += _fieldPrefixSize + fieldLength;
            }

            return payload;
        }

        internal static byte[] BuildBinary(byte algorithmId, params byte[][] fields)
        {
            var fieldLengths = new int[fields.Length];

            for (var index = 0; index < fields.Length; index++)
            {
                fieldLengths[index] = fields[index].Length;
            }

            var payload = CreateBinary(algorithmId, fieldLengths, out var fieldOffsets);

            for (var index = 0; index < fields.Length; index++)
            {
                Array.Copy(fields[index], 0, payload, fieldOffsets[index], fields[index].Length);
            }

            return payload;
        }

        internal static (int Offset, int Length)[] ParseBinary(byte[] payload, byte expectedAlgorithmId, int expectedFieldCount, string paramName)
        {
            if (payload is null || payload.Length < _headerSize)
            {
                throw CreateInvalidPayloadException(paramName);
            }

            for (var index = 0; index < _magicBytes.Length; index++)
            {
                if (payload[index] != _magicBytes[index])
                {
                    throw CreateInvalidPayloadException(paramName);
                }
            }

            if (payload[4] != FormatVersion || payload[5] != expectedAlgorithmId || payload[6] != expectedFieldCount)
            {
                throw CreateInvalidPayloadException(paramName);
            }

            var fields = new (int Offset, int Length)[expectedFieldCount];
            var position = _headerSize;

            for (var index = 0; index < expectedFieldCount; index++)
            {
                if (position + _fieldPrefixSize > payload.Length)
                {
                    throw CreateInvalidPayloadException(paramName);
                }

                var fieldLength =
                    payload[position] |
                    (payload[position + 1] << 8) |
                    (payload[position + 2] << 16) |
                    (payload[position + 3] << 24);

                if (fieldLength < 0 || position + _fieldPrefixSize + fieldLength > payload.Length)
                {
                    throw CreateInvalidPayloadException(paramName);
                }

                fields[index] = (position + _fieldPrefixSize, fieldLength);
                position += _fieldPrefixSize + fieldLength;
            }

            if (position != payload.Length)
            {
                throw CreateInvalidPayloadException(paramName); // trailing bytes
            }

            return fields;
        }

        internal static byte[] GetField(byte[] payload, (int Offset, int Length) field)
        {
            var bytes = new byte[field.Length];

            Array.Copy(payload, field.Offset, bytes, 0, field.Length);

            return bytes;
        }

        internal static byte[][] GetFields(byte[] payload, (int Offset, int Length)[] fields)
        {
            var result = new byte[fields.Length][];

            for (var index = 0; index < fields.Length; index++)
            {
                result[index] = GetField(payload, fields[index]);
            }

            return result;
        }

        #endregion Binary form


        #region String form

        internal static string BuildString(string algorithmName, string parameters, params byte[][] fields)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.Append('$').Append(algorithmName).Append("$v=").Append(FormatVersion);

            if (!string.IsNullOrEmpty(parameters))
            {
                stringBuilder.Append('$').Append(parameters);
            }

            foreach (var field in fields)
            {
                stringBuilder.Append('$').Append(ToUnpaddedBase64(field));
            }

            return stringBuilder.ToString();
        }

        internal static (string Parameters, byte[][] Fields) ParseString(
            string payload,
            string expectedAlgorithmName,
            int expectedFieldCount,
            bool hasParameters,
            string paramName)
        {
            if (string.IsNullOrWhiteSpace(payload))
            {
                throw CreateInvalidPayloadException(paramName);
            }

            var parts = payload.Split('$');
            var expectedPartCount = 3 + (hasParameters ? 1 : 0) + expectedFieldCount;

            if (parts.Length != expectedPartCount ||
                parts[0].Length != 0 ||
                parts[1] != expectedAlgorithmName ||
                parts[2] != "v=" + FormatVersion)
            {
                throw CreateInvalidPayloadException(paramName);
            }

            var fieldStartIndex = hasParameters ? 4 : 3;
            var parameters = hasParameters ? parts[3] : null;
            var fields = new byte[expectedFieldCount][];

            for (var index = 0; index < expectedFieldCount; index++)
            {
                fields[index] = FromUnpaddedBase64(parts[fieldStartIndex + index], paramName);
            }

            return (parameters, fields);
        }

        internal static string ToUnpaddedBase64(byte[] data)
            => Convert.ToBase64String(data).TrimEnd('=');

        internal static byte[] FromUnpaddedBase64(string base64String, string paramName)
        {
            var paddingLength = (4 - (base64String.Length % 4)) % 4;

            if (base64String.Length == 0 || paddingLength == 3)
            {
                throw CreateInvalidPayloadException(paramName);
            }

            try
            {
                return Convert.FromBase64String(base64String + new string('=', paddingLength));
            }
            catch (FormatException)
            {
                throw CreateInvalidPayloadException(paramName);
            }
        }

        #endregion String form

        internal static ArgumentException CreateInvalidPayloadException(string paramName)
            => CreateFormattedArgumentException(LibraryResources.Validation_InvalidPayloadFormat, paramName);
    }
}
