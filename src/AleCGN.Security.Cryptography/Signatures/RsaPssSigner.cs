using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;

namespace AleCGN.Security.Cryptography.Signatures
{
    /// <summary>
    /// RSA-PSS digital signatures (SHA-256 by default).
    /// Keys are provided as PEM-encoded strings (use <see cref="RsaKeyPairHelper"/> to generate them);
    /// the private key is required for signing, the public key for verification.
    /// </summary>
    public class RsaPssSigner : DigitalSignerBase, IRsaPssSigner
    {
        private readonly HashAlgorithmKind _hashAlgorithmKind;

        public RsaPssSigner(
            IEncoder encoder,
            string privateKeyPem = null,
            string publicKeyPem = null,
            HashAlgorithmKind hashAlgorithmKind = HashAlgorithmKind.SHA256)
            : base(encoder, privateKeyPem, publicKeyPem)
        {
            _hashAlgorithmKind = hashAlgorithmKind;
        }

        protected override ISigner CreateSigner()
            => new PssSigner(new RsaEngine(), DigestHelper.CreateDigest(_hashAlgorithmKind));
    }
}
