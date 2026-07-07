namespace AleCGN.Security.Cryptography.KeyDerivation
{
    /// <summary>
    /// Result of an async key derivation that generates a random salt
    /// (the async counterpart of the DeriveKey overloads with an out salt parameter).
    /// </summary>
    public class KeyDerivationResult
    {
        public KeyDerivationResult(byte[] key, byte[] salt)
        {
            Key = key;
            Salt = salt;
        }


        public byte[] Key { get; }

        public byte[] Salt { get; }
    }

    /// <summary>
    /// Result of an async text key derivation that generates a random salt,
    /// with both values encoded by the configured IEncoder.
    /// </summary>
    public class EncodedKeyDerivationResult
    {
        public EncodedKeyDerivationResult(string encodedKey, string encodedSalt)
        {
            EncodedKey = encodedKey;
            EncodedSalt = encodedSalt;
        }


        public string EncodedKey { get; }

        public string EncodedSalt { get; }
    }
}
