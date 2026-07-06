using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;

namespace AleCGN.Security.Cryptography.Hmac
{
    public class HMACSHA384 : HmacBase, IHMACSHA384
    {
        public HMACSHA384(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA384) { }

        public HMACSHA384(IEncoder encoder, byte[] key) : base(encoder, HashAlgorithmKind.SHA384, key) { }

        public HMACSHA384(IEncoder encoder, string encodedKey) : base(encoder, HashAlgorithmKind.SHA384, encodedKey) { }
    }
}
