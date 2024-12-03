#if NETSTANDARD2_1

using AleCGN.Security.Cryptography.Encoders;
using System.Security.Authentication;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA384 : HashBase, ISHA384
    {
        public SHA384(IEncoder encoder) : base(encoder, HashAlgorithmType.Sha384) { }
    }
}

#endif