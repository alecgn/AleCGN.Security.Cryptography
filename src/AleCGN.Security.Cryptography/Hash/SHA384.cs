using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA384 : HashBase, ISHA384
    {
        public SHA384(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA384) { }
    }
}
