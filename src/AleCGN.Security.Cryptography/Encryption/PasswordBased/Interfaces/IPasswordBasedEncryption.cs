namespace AleCGN.Security.Cryptography.Encryption.PasswordBased
{
    public interface IPasswordBasedEncryption
    {
        byte[] EncryptData(byte[] data, string password);

        string EncryptText(string text, string password);

        byte[] DecryptData(byte[] encryptedDataWithMetadata, string password);

        string DecryptText(string encryptedTextWithMetadata, string password);
    }
}
