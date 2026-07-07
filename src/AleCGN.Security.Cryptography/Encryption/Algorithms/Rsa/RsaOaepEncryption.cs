using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.Algorithms.Rsa
{
    /// <summary>
    /// RSA encryption with OAEP padding (SHA-256 by default). Suitable for small payloads such as
    /// symmetric keys; for large data, encrypt with AES-GCM and protect the AES key with this class.
    /// Keys are provided as PEM-encoded strings (use <see cref="RsaKeyPairHelper"/> to generate them).
    /// </summary>
    public class RsaOaepEncryption : IRsaOaepEncryption
    {
        private readonly IEncoder _encoder;
        private readonly HashAlgorithmKind _oaepDigest;
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly AsymmetricKeyParameter _privateKey;

        public RsaOaepEncryption(
            IEncoder encoder,
            string publicKeyPem = null,
            string privateKeyPem = null,
            HashAlgorithmKind oaepDigest = HashAlgorithmKind.SHA256)
        {
            _encoder = encoder;
            _oaepDigest = oaepDigest;

            if (!string.IsNullOrWhiteSpace(publicKeyPem))
            {
                _publicKey = PemKeyHelper.ReadPublicKey(publicKeyPem, nameof(publicKeyPem));
            }

            if (!string.IsNullOrWhiteSpace(privateKeyPem))
            {
                _privateKey = PemKeyHelper.ReadPrivateKey(privateKeyPem, nameof(privateKeyPem));
            }
        }

        public byte[] EncryptData(byte[] data)
        {
            CheckInputData(data, nameof(data));

            if (_publicKey is null)
            {
                throw new CryptographicException(LibraryResources.Validation_PublicKeyNotSet);
            }

            var engine = CreateEngine();

            engine.Init(true, _publicKey);

            var ciphertext = engine.ProcessBlock(data, 0, data.Length);

            // Self-describing envelope: OAEP digest | ciphertext.
            return PayloadFormat.BuildBinary(PayloadAlgorithms.RsaOaep, new[] { (byte)_oaepDigest }, ciphertext);
        }

        public string EncryptText(string text)
        {
            CheckInputText(text, nameof(text));

            var payload = EncryptData(text.ToUTF8Bytes());
            var fields = PayloadFormat.ParseBinary(payload, PayloadAlgorithms.RsaOaep, 2, nameof(text));

            return PayloadFormat.BuildString(GetAlgorithmName(), null, PayloadFormat.GetField(payload, fields[1]));
        }

        public byte[] DecryptData(byte[] encryptedData)
        {
            CheckInputData(encryptedData, nameof(encryptedData));

            if (_privateKey is null)
            {
                throw new CryptographicException(LibraryResources.Validation_PrivateKeyNotSet);
            }

            var fields = PayloadFormat.ParseBinary(encryptedData, PayloadAlgorithms.RsaOaep, 2, nameof(encryptedData));

            if (fields[0].Length != 1 || encryptedData[fields[0].Offset] != (byte)_oaepDigest || fields[1].Length == 0)
            {
                throw PayloadFormat.CreateInvalidPayloadException(nameof(encryptedData));
            }

            var engine = CreateEngine();

            engine.Init(false, _privateKey);

            return engine.ProcessBlock(encryptedData, fields[1].Offset, fields[1].Length);
        }

        public string DecryptText(string encryptedText)
        {
            CheckInputText(encryptedText, nameof(encryptedText));

            var (_, fields) = PayloadFormat.ParseString(
                encryptedText, GetAlgorithmName(), 1, hasParameters: false, nameof(encryptedText));

            var payload = PayloadFormat.BuildBinary(PayloadAlgorithms.RsaOaep, new[] { (byte)_oaepDigest }, fields[0]);

            return DecryptData(payload).ToUTF8String();
        }

        private string GetAlgorithmName()
            => "rsa-oaep-" + DigestHelper.GetAlgorithmToken(_oaepDigest);

        public Task<byte[]> EncryptDataAsync(byte[] data, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptData(data), cancellationToken);

        public Task<string> EncryptTextAsync(string text, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptText(text), cancellationToken);

        public Task<byte[]> DecryptDataAsync(byte[] encryptedData, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptData(encryptedData), cancellationToken);

        public Task<string> DecryptTextAsync(string encryptedText, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptText(encryptedText), cancellationToken);

        private OaepEncoding CreateEngine()
            => new OaepEncoding(new RsaEngine(), DigestHelper.CreateDigest(_oaepDigest));

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
