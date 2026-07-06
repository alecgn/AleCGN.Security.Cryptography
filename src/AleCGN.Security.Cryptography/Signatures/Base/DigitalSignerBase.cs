using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Signatures
{
    public abstract class DigitalSignerBase : IDigitalSigner
    {
        private readonly IEncoder _encoder;
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly AsymmetricKeyParameter _privateKey;

        protected DigitalSignerBase(IEncoder encoder, string privateKeyPem, string publicKeyPem)
        {
            _encoder = encoder;

            if (!string.IsNullOrWhiteSpace(privateKeyPem))
            {
                _privateKey = PemKeyHelper.ReadPrivateKey(privateKeyPem, nameof(privateKeyPem));
            }

            if (!string.IsNullOrWhiteSpace(publicKeyPem))
            {
                _publicKey = PemKeyHelper.ReadPublicKey(publicKeyPem, nameof(publicKeyPem));
            }
        }

        protected abstract ISigner CreateSigner();

        public byte[] SignData(byte[] data)
        {
            CheckInputData(data, nameof(data));

            if (_privateKey is null)
            {
                throw new CryptographicException(LibraryResources.Validation_PrivateKeyNotSet);
            }

            var signer = CreateSigner();

            signer.Init(true, _privateKey);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        public string SignText(string text)
        {
            CheckInputText(text, nameof(text));

            return _encoder.Encode(SignData(text.ToUTF8Bytes()));
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            CheckInputData(data, nameof(data));
            CheckInputData(signature, nameof(signature));

            if (_publicKey is null)
            {
                throw new CryptographicException(LibraryResources.Validation_PublicKeyNotSet);
            }

            var signer = CreateSigner();

            signer.Init(false, _publicKey);
            signer.BlockUpdate(data, 0, data.Length);

            try
            {
                return signer.VerifySignature(signature);
            }
            catch
            {
                // Malformed signatures must fail verification, not throw.
                return false;
            }
        }

        public bool VerifyTextSignature(string text, string encodedSignature)
        {
            CheckInputText(text, nameof(text));
            CheckInputText(encodedSignature, nameof(encodedSignature));

            return VerifySignature(text.ToUTF8Bytes(), _encoder.Decode(encodedSignature));
        }

        private void CheckInputData(byte[] inputData, string paramName)
        {
            if (inputData == null || inputData.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, paramName);
            }
        }

        private void CheckInputText(string inputText, string paramName)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, paramName);
            }
        }
    }
}
