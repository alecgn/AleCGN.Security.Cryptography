using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Signatures;
using System;
using System.Security.Cryptography;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Asymmetric
{
    public class SignerTests
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private static readonly AsymmetricKeyPair _rsaKeyPair = new RsaKeyPairHelper().GenerateKeyPair();
        private static readonly AsymmetricKeyPair _ecdsaKeyPair = new EcdsaKeyPairHelper().GenerateKeyPair();

        [Fact]
        public void RsaPss_SignAndVerify()
        {
            var signer = new RsaPssSigner(_encoder, _rsaKeyPair.PrivateKeyPem, _rsaKeyPair.PublicKeyPem);
            var signature = signer.SignText("important document");

            Assert.StartsWith("$rsa-pss-sha256$v=1$", signature);
            Assert.True(signer.VerifyTextSignature("important document", signature));
            Assert.False(signer.VerifyTextSignature("tampered document", signature));
        }

        [Fact]
        public void Ecdsa_SignText_ProducesSelfDescribingFormat()
        {
            var signer = new EcdsaSigner(_encoder, _ecdsaKeyPair.PrivateKeyPem, _ecdsaKeyPair.PublicKeyPem);

            Assert.StartsWith("$ecdsa-sha256$v=1$", signer.SignText("document"));
        }

        [Fact]
        public void RsaPss_SignaturesAreRandomized_BothVerify()
        {
            var signer = new RsaPssSigner(_encoder, _rsaKeyPair.PrivateKeyPem, _rsaKeyPair.PublicKeyPem);
            var signature1 = signer.SignText("document");
            var signature2 = signer.SignText("document");

            Assert.NotEqual(signature1, signature2);
            Assert.True(signer.VerifyTextSignature("document", signature1));
            Assert.True(signer.VerifyTextSignature("document", signature2));
        }

        [Fact]
        public void RsaPss_VerifierNeedsOnlyPublicKey()
        {
            var signer = new RsaPssSigner(_encoder, privateKeyPem: _rsaKeyPair.PrivateKeyPem);
            var verifier = new RsaPssSigner(_encoder, publicKeyPem: _rsaKeyPair.PublicKeyPem);

            Assert.True(verifier.VerifyTextSignature("document", signer.SignText("document")));
        }

        [Theory]
        [InlineData(EcdsaCurves.NistP256)]
        [InlineData(EcdsaCurves.NistP384)]
        [InlineData(EcdsaCurves.NistP521)]
        public void Ecdsa_SignAndVerify_AllCurves(EcdsaCurves curve)
        {
            var keyPair = new EcdsaKeyPairHelper().GenerateKeyPair(curve);
            var signer = new EcdsaSigner(_encoder, keyPair.PrivateKeyPem, keyPair.PublicKeyPem);
            var signature = signer.SignText("important document");

            Assert.True(signer.VerifyTextSignature("important document", signature));
            Assert.False(signer.VerifyTextSignature("tampered document", signature));
        }

        [Fact]
        public void Ecdsa_WrongKey_FailsVerification()
        {
            var signer = new EcdsaSigner(_encoder, _ecdsaKeyPair.PrivateKeyPem);
            var otherKeyPair = new EcdsaKeyPairHelper().GenerateKeyPair();
            var wrongVerifier = new EcdsaSigner(_encoder, publicKeyPem: otherKeyPair.PublicKeyPem);

            Assert.False(wrongVerifier.VerifyTextSignature("document", signer.SignText("document")));
        }

        [Fact]
        public void MalformedSignature_ReturnsFalse_DoesNotThrow()
        {
            var verifier = new EcdsaSigner(_encoder, publicKeyPem: _ecdsaKeyPair.PublicKeyPem);

            Assert.False(verifier.VerifySignature(Utf8("document"), Utf8("garbage signature")));
        }

        [Fact]
        public void Sign_WithoutPrivateKey_Throws()
        {
            var signer = new RsaPssSigner(_encoder, publicKeyPem: _rsaKeyPair.PublicKeyPem);

            Assert.Throws<CryptographicException>(() => signer.SignText("document"));
        }

        [Fact]
        public void Verify_WithoutPublicKey_Throws()
        {
            var signer = new RsaPssSigner(_encoder, privateKeyPem: _rsaKeyPair.PrivateKeyPem);
            var signature = signer.SignText("document");

            Assert.Throws<CryptographicException>(() => signer.VerifyTextSignature("document", signature));
        }

        [Fact]
        public void CrossAlgorithm_SignaturesDoNotVerify()
        {
            var rsaSigner = new RsaPssSigner(_encoder, _rsaKeyPair.PrivateKeyPem, _rsaKeyPair.PublicKeyPem);
            var ecdsaVerifier = new EcdsaSigner(_encoder, publicKeyPem: _ecdsaKeyPair.PublicKeyPem);

            Assert.False(ecdsaVerifier.VerifyTextSignature("document", rsaSigner.SignText("document")));
        }
    }
}
