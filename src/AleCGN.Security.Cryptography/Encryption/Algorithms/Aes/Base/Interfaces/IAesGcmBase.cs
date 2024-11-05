namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Aes
{
    public interface IAesGcmBase : IEncryptionOperations
    {
        void SetOrUpdateKey(byte[] key);

        void SetOrUpdateKey(string encodedKey);
    }
}