namespace AleCGN.Security.Cryptography.Hash
{
    public class HashResult
    {
        public HashResult(string encodedHash, byte[] hashBytes)
        {
            EncodedHash = encodedHash;
            HashBytes = hashBytes;
        }


        public string EncodedHash { get; }

        public byte[] HashBytes { get; }
    }

    public class FileHashResult : HashResult
    {
        public FileHashResult(string encodedHash, byte[] hashBytes) : base(encodedHash, hashBytes) { }
    }
}
