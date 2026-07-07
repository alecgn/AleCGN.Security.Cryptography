using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace AleCGN.Security.Cryptography.Signatures
{
    /// <summary>
    /// ECDSA digital signatures (SHA-256 by default), producing self-describing signature
    /// payloads such as "$ecdsa-sha256$v=1$&lt;signature&gt;".
    /// Keys are provided as PEM-encoded strings (use <see cref="EcdsaKeyPairHelper"/> to generate them);
    /// the private key is required for signing, the public key for verification.
    /// </summary>
    public class EcdsaSigner : DigitalSignerBase, IEcdsaSigner
    {
        private readonly string _signerAlgorithm;

        public EcdsaSigner(
            IEncoder encoder,
            string privateKeyPem = null,
            string publicKeyPem = null,
            HashAlgorithmKind hashAlgorithmKind = HashAlgorithmKind.SHA256)
            : base(encoder, privateKeyPem, publicKeyPem, hashAlgorithmKind)
        {
            _signerAlgorithm = GetSignerAlgorithm(hashAlgorithmKind);
        }

        protected override byte AlgorithmId => PayloadAlgorithms.Ecdsa;

        protected override string AlgorithmFamilyName => "ecdsa";

        protected override ISigner CreateSigner()
            => SignerUtilities.GetSigner(_signerAlgorithm);

        private static string GetSignerAlgorithm(HashAlgorithmKind hashAlgorithmKind)
        {
            switch (hashAlgorithmKind)
            {
                case HashAlgorithmKind.SHA1:
                    return "SHA-1withECDSA";
                case HashAlgorithmKind.SHA256:
                    return "SHA-256withECDSA";
                case HashAlgorithmKind.SHA384:
                    return "SHA-384withECDSA";
                case HashAlgorithmKind.SHA512:
                    return "SHA-512withECDSA";
                default:
                    throw new CryptographicException($"Unsupported hash algorithm for ECDSA: {hashAlgorithmKind}.");
            }
        }
    }
}
