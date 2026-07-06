namespace AleCGN.Security.Cryptography.KeyDerivation
{
    public interface IArgon2id
    {
        byte[] DeriveKey(byte[] password, out byte[] salt);

        byte[] DeriveKey(byte[] password, byte[] salt);

        string DeriveTextKey(string password, out string encodedSalt);

        string DeriveTextKey(string password, string encodedSalt);

        bool VerifyKey(byte[] password, byte[] salt, byte[] expectedDerivedKey);

        bool VerifyTextKey(string password, string encodedSalt, string encodedExpectedDerivedKey);
    }
}
