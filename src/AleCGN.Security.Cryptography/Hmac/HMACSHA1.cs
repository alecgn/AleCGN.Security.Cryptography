using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;

namespace AleCGN.Security.Cryptography.Hmac
{
    public class HMACSHA1 : HmacBase, IHMACSHA1
    {
        public HMACSHA1(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA1) { }

        public HMACSHA1(IEncoder encoder, byte[] key) : base(encoder, HashAlgorithmKind.SHA1, key) { }

        public HMACSHA1(IEncoder encoder, string encodedKey) : base(encoder, HashAlgorithmKind.SHA1, encodedKey) { }
    }
}
