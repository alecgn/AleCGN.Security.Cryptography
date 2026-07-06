using AleCGN.Security.Cryptography.Encoders;

namespace AleCGN.Security.Cryptography.Hash
{
    public class MD5 : HashBase, IMD5
    {
        public MD5(IEncoder encoder) : base(encoder, HashAlgorithmKind.MD5) { }
    }
}
