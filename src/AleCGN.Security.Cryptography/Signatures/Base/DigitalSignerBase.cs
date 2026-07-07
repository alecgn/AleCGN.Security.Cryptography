using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Signatures
{
    public abstract class DigitalSignerBase : IDigitalSigner
    {
        private readonly IEncoder _encoder;
        private readonly HashAlgorithmKind _hashAlgorithmKind;
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly AsymmetricKeyParameter _privateKey;

        protected DigitalSignerBase(IEncoder encoder, string privateKeyPem, string publicKeyPem, HashAlgorithmKind hashAlgorithmKind)
        {
            _encoder = encoder;
            _hashAlgorithmKind = hashAlgorithmKind;

            if (!string.IsNullOrWhiteSpace(privateKeyPem))
            {
                _privateKey = PemKeyHelper.ReadPrivateKey(privateKeyPem, nameof(privateKeyPem));
            }

            if (!string.IsNullOrWhiteSpace(publicKeyPem))
            {
                _publicKey = PemKeyHelper.ReadPublicKey(publicKeyPem, nameof(publicKeyPem));
            }
        }

        protected HashAlgorithmKind HashAlgorithm => _hashAlgorithmKind;

        protected abstract byte AlgorithmId { get; }

        protected abstract string AlgorithmFamilyName { get; }

        protected abstract ISigner CreateSigner();

        public byte[] SignData(byte[] data)
        {
            CheckInputData(data, nameof(data));

            // Self-describing envelope: digest | signature.
            return PayloadFormat.BuildBinary(AlgorithmId, new[] { (byte)_hashAlgorithmKind }, SignCore(data));
        }

        public string SignText(string text)
        {
            CheckInputText(text, nameof(text));

            return PayloadFormat.BuildString(GetAlgorithmName(), null, SignCore(text.ToUTF8Bytes()));
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            CheckInputData(data, nameof(data));
            CheckInputData(signature, nameof(signature));

            (int Offset, int Length)[] fields;

            try
            {
                fields = PayloadFormat.ParseBinary(signature, AlgorithmId, 2, nameof(signature));
            }
            catch
            {
                // Malformed signatures must fail verification, not throw.
                return false;
            }

            if (fields[0].Length != 1 || signature[fields[0].Offset] != (byte)_hashAlgorithmKind)
            {
                return false;
            }

            return VerifyCore(data, PayloadFormat.GetField(signature, fields[1]));
        }

        public bool VerifyTextSignature(string text, string encodedSignature)
        {
            CheckInputText(text, nameof(text));
            CheckInputText(encodedSignature, nameof(encodedSignature));

            byte[][] fields;

            try
            {
                (_, fields) = PayloadFormat.ParseString(
                    encodedSignature, GetAlgorithmName(), 1, hasParameters: false, nameof(encodedSignature));
            }
            catch
            {
                return false;
            }

            return VerifyCore(text.ToUTF8Bytes(), fields[0]);
        }

        public Task<byte[]> SignDataAsync(byte[] data, CancellationToken cancellationToken = default)
            => Task.Run(() => SignData(data), cancellationToken);

        public Task<string> SignTextAsync(string text, CancellationToken cancellationToken = default)
            => Task.Run(() => SignText(text), cancellationToken);

        public Task<bool> VerifySignatureAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifySignature(data, signature), cancellationToken);

        public Task<bool> VerifyTextSignatureAsync(string text, string encodedSignature, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyTextSignature(text, encodedSignature), cancellationToken);

        private string GetAlgorithmName()
            => AlgorithmFamilyName + "-" + DigestHelper.GetAlgorithmToken(_hashAlgorithmKind);

        private byte[] SignCore(byte[] data)
        {
            if (_privateKey is null)
            {
                throw new CryptographicException(LibraryResources.Validation_PrivateKeyNotSet);
            }

            var signer = CreateSigner();

            signer.Init(true, _privateKey);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        private bool VerifyCore(byte[] data, byte[] rawSignature)
        {
            if (_publicKey is null)
            {
                throw new CryptographicException(LibraryResources.Validation_PublicKeyNotSet);
            }

            var signer = CreateSigner();

            signer.Init(false, _publicKey);
            signer.BlockUpdate(data, 0, data.Length);

            try
            {
                return signer.VerifySignature(rawSignature);
            }
            catch
            {
                return false;
            }
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
