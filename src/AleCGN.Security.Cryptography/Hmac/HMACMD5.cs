using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;

namespace AleCGN.Security.Cryptography.Hmac
{
    public class HMACMD5 : HmacBase, IHMACMD5
    {
        public HMACMD5(IEncoder encoder) : base(encoder, HashAlgorithmKind.MD5) { }

        public HMACMD5(IEncoder encoder, byte[] key) : base(encoder, HashAlgorithmKind.MD5, key) { }

        public HMACMD5(IEncoder encoder, string encodedKey) : base(encoder, HashAlgorithmKind.MD5, encodedKey) { }
    }
}
