namespace AleCGN.Security.Cryptography.Encoders
{
    public interface IEncoder
    {
        string Encode(byte[] data);

        byte[] Decode(string encodedData);
    }
}
