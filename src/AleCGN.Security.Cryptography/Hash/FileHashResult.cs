namespace AleCGN.Security.Cryptography.Hash
{
    public class FileHashResult
    {
        public FileHashResult(string encodedHash, byte[] hashBytes)
        {
            EncodedHash = encodedHash;
            HashBytes = hashBytes;
        }


        public string EncodedHash { get; }

        public byte[] HashBytes { get; }
    }
}
