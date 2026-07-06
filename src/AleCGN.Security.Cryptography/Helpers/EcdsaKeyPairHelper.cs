using AleCGN.Security.Cryptography.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace AleCGN.Security.Cryptography
{
    public class EcdsaKeyPairHelper : IEcdsaKeyPairHelper
    {
        public AsymmetricKeyPair GenerateKeyPair(EcdsaCurves curve = EcdsaCurves.NistP256)
        {
            var generator = new ECKeyPairGenerator();

            generator.Init(new ECKeyGenerationParameters(GetCurveOid(curve), new SecureRandom()));

            var keyPair = generator.GenerateKeyPair();

            return new AsymmetricKeyPair(
                PemKeyHelper.WritePem(keyPair.Public),
                PemKeyHelper.WritePem(keyPair.Private)
            );
        }

        private static DerObjectIdentifier GetCurveOid(EcdsaCurves curve)
        {
            switch (curve)
            {
                case EcdsaCurves.NistP256:
                    return SecObjectIdentifiers.SecP256r1;
                case EcdsaCurves.NistP384:
                    return SecObjectIdentifiers.SecP384r1;
                case EcdsaCurves.NistP521:
                    return SecObjectIdentifiers.SecP521r1;
                default:
                    throw new ArgumentOutOfRangeException(nameof(curve));
            }
        }
    }
}
