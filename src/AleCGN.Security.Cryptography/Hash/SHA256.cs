#if NETSTANDARD2_1

using AleCGN.Security.Cryptography.Encoders;
using System.Security.Authentication;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA256 : HashBase, ISHA256
    {
        public SHA256(IEncoder encoder) : base(encoder, HashAlgorithmType.Sha256) { }
    }
}

#endif