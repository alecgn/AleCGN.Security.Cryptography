namespace AleCGN.Security.Cryptography.Encoders.Extensions
{
    internal static class EncodingExtensions
    {
        internal static byte[] ToUTF8Bytes(this string text)
            => System.Text.Encoding.UTF8.GetBytes(text);

        internal static string ToUTF8String(this byte[] data)
            => System.Text.Encoding.UTF8.GetString(data);
    }
}
