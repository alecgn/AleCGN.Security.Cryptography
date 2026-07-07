using AleCGN.Security.Cryptography.Hash;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace AleCGN.Security.Cryptography.Helpers
{
    internal static class DigestHelper
    {
        internal static IDigest CreateDigest(HashAlgorithmKind hashAlgorithmKind)
        {
            switch (hashAlgorithmKind)
            {
                case HashAlgorithmKind.MD5:
                    return new MD5Digest();
                case HashAlgorithmKind.SHA1:
                    return new Sha1Digest();
                case HashAlgorithmKind.SHA256:
                    return new Sha256Digest();
                case HashAlgorithmKind.SHA384:
                    return new Sha384Digest();
                case HashAlgorithmKind.SHA512:
                    return new Sha512Digest();
                default:
                    throw new CryptographicException($"Unsupported hash algorithm: {hashAlgorithmKind}.");
            }
        }

        internal static string GetAlgorithmToken(HashAlgorithmKind hashAlgorithmKind)
        {
            switch (hashAlgorithmKind)
            {
                case HashAlgorithmKind.MD5:
                    return "md5";
                case HashAlgorithmKind.SHA1:
                    return "sha1";
                case HashAlgorithmKind.SHA256:
                    return "sha256";
                case HashAlgorithmKind.SHA384:
                    return "sha384";
                case HashAlgorithmKind.SHA512:
                    return "sha512";
                default:
                    throw new CryptographicException($"Unsupported hash algorithm: {hashAlgorithmKind}.");
            }
        }

        internal static HashAlgorithmName GetHashAlgorithmName(HashAlgorithmKind hashAlgorithmKind)
        {
            switch (hashAlgorithmKind)
            {
                case HashAlgorithmKind.MD5:
                    return HashAlgorithmName.MD5;
                case HashAlgorithmKind.SHA1:
                    return HashAlgorithmName.SHA1;
                case HashAlgorithmKind.SHA256:
                    return HashAlgorithmName.SHA256;
                case HashAlgorithmKind.SHA384:
                    return HashAlgorithmName.SHA384;
                case HashAlgorithmKind.SHA512:
                    return HashAlgorithmName.SHA512;
                default:
                    throw new CryptographicException($"Unsupported hash algorithm: {hashAlgorithmKind}.");
            }
        }
    }
}
