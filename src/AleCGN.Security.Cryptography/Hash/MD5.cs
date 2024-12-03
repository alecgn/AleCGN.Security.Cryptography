using AleCGN.Security.Cryptography.Encoders;
using System.Security.Authentication;

namespace AleCGN.Security.Cryptography.Hash
{
    public class MD5 : HashBase, IMD5
    {
        public MD5(IEncoder encoder) : base(encoder, HashAlgorithmType.Md5) { }
    }
}
