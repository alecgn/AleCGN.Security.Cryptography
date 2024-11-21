namespace AleCGN.Security.Cryptography.Encoders
{
    public interface IEncoder
    {
        string Encode(byte[] data);

        string Encode(string text);

        byte[] Decode(string encodedData);
    }
}
