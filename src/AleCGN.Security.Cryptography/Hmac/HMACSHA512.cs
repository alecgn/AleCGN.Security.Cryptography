using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;

namespace AleCGN.Security.Cryptography.Hmac
{
    public class HMACSHA512 : HmacBase, IHMACSHA512
    {
        public HMACSHA512(IEncoder encoder) : base(encoder, HashAlgorithmKind.SHA512) { }

        public HMACSHA512(IEncoder encoder, byte[] key) : base(encoder, HashAlgorithmKind.SHA512, key) { }

        public HMACSHA512(IEncoder encoder, string encodedKey) : base(encoder, HashAlgorithmKind.SHA512, encodedKey) { }
    }
}
