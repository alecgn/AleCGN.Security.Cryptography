namespace AleCGN.Security.Cryptography.Encryption
{
    public interface IEncryptionOperations
    {
        byte[] EncryptData(byte[] data);

        string EncryptText(string text);

        byte[] DecryptData(byte[] encryptedData);

        string DecryptText(string encryptedText);
    }
}