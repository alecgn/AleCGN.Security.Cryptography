using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA256 : HashBase, ISHA256
    {
        public SHA256(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA256) { }
    }
}
