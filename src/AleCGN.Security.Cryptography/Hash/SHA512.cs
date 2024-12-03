#if NETSTANDARD2_1

using AleCGN.Security.Cryptography.Encoders;
using System.Security.Authentication;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA512 : HashBase, ISHA512
    {
        public SHA512(IEncoder encoder) : base(encoder, HashAlgorithmType.Sha512) { }
    }
}

#endif