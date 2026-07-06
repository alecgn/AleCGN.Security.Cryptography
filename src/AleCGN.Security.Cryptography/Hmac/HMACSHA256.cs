using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;

namespace AleCGN.Security.Cryptography.Hmac
{
    public class HMACSHA256 : HmacBase, IHMACSHA256
    {
        public HMACSHA256(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA256) { }

        public HMACSHA256(IEncoder encoder, byte[] key) : base(encoder, HashAlgorithmKind.SHA256, key) { }

        public HMACSHA256(IEncoder encoder, string encodedKey) : base(encoder, HashAlgorithmKind.SHA256, encodedKey) { }
    }
}
