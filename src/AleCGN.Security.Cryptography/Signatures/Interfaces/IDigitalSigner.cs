namespace AleCGN.Security.Cryptography.Signatures
{
    public interface IDigitalSigner
    {
        byte[] SignData(byte[] data);

        string SignText(string text);

        bool VerifySignature(byte[] data, byte[] signature);

        bool VerifyTextSignature(string text, string encodedSignature);
    }
}
