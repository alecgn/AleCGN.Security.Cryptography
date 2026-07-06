using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA512 : HashBase, ISHA512
    {
        public SHA512(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA512) { }
    }
}
