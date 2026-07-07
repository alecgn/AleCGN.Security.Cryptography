using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;
#if NET8_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged
{
    /// <summary>
    /// This class and its methods are Windows-only, because ProtectedData is a wrapper/binding around native DPAPI (Data Protection API), only available on Windows.
    /// Using this class, you alleviate the difficult problem of explicitly generating, storing and managing a cryptographic key.
    /// </summary>
#if NET8_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public class DataProtection : IDataProtection
    {
        #region Fields

        private readonly IEncoder _encoder;
        private readonly DataProtectionConfiguration _configuration;

        #endregion Fields


        #region Constructors

        public DataProtection(IEncoder encoder, DataProtectionConfiguration configuration)
        {
            _encoder = encoder;
            _configuration = configuration;
        }

        #endregion Constructors


        #region Public methods

        public byte[] EncryptData(byte[] data)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            var protectedBlob = ProtectedData.Protect(data, _configuration.OptionalEntropy, _configuration.Scope);

            return PayloadFormat.BuildBinary(PayloadAlgorithms.Dpapi, protectedBlob);
        }

        public string EncryptText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            var payload = EncryptData(text.ToUTF8Bytes());
            var fields = PayloadFormat.ParseBinary(payload, PayloadAlgorithms.Dpapi, 1, nameof(text));

            return PayloadFormat.BuildString(PayloadAlgorithms.DpapiName, null, PayloadFormat.GetField(payload, fields[0]));
        }

        public byte[] DecryptData(byte[] encryptedData)
        {
            if (encryptedData is null || encryptedData.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(encryptedData));
            }

            var fields = PayloadFormat.ParseBinary(encryptedData, PayloadAlgorithms.Dpapi, 1, nameof(encryptedData));
            var protectedBlob = PayloadFormat.GetField(encryptedData, fields[0]);

            return ProtectedData.Unprotect(protectedBlob, _configuration.OptionalEntropy, _configuration.Scope);
        }

        public string DecryptText(string encryptedText)
        {
            if (string.IsNullOrWhiteSpace(encryptedText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encryptedText));
            }

            var (_, fields) = PayloadFormat.ParseString(
                encryptedText, PayloadAlgorithms.DpapiName, 1, hasParameters: false, nameof(encryptedText));

            var payload = PayloadFormat.BuildBinary(PayloadAlgorithms.Dpapi, fields[0]);

            return DecryptData(payload).ToUTF8String();
        }

        public Task<byte[]> EncryptDataAsync(byte[] data, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptData(data), cancellationToken);

        public Task<string> EncryptTextAsync(string text, CancellationToken cancellationToken = default)
            => Task.Run(() => EncryptText(text), cancellationToken);

        public Task<byte[]> DecryptDataAsync(byte[] encryptedData, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptData(encryptedData), cancellationToken);

        public Task<string> DecryptTextAsync(string encryptedText, CancellationToken cancellationToken = default)
            => Task.Run(() => DecryptText(encryptedText), cancellationToken);

        #endregion Public methods
    }

#if NET8_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public class DataProtectionConfiguration
    {
        public DataProtectionConfiguration(byte[] optionalEntropy, DataProtectionScope scope)
        {
            OptionalEntropy = optionalEntropy;
            Scope = scope;
        }


        public byte[] OptionalEntropy { get; set; }

        public DataProtectionScope Scope { get; set; }


        public static DataProtectionConfiguration Default
            => new DataProtectionConfiguration(optionalEntropy: null, DataProtectionScope.LocalMachine);
    }
}