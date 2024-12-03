using AleCGN.Security.Cryptography.Encoders;
using System.Security.Authentication;

namespace AleCGN.Security.Cryptography.Hash
{
    public class SHA1 : HashBase, ISHA1
    {
        public SHA1(IEncoder encoder) : base(encoder, HashAlgorithmType.Sha1) { }
    }
}
