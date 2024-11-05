#if NETSTANDARD2_0

using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System.Security.Cryptography;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged
{
    /// <summary>
    /// This class and its methods are Windows-only, because ProtectedData is a wrapper/binding around native DPAPI (Data Protection API), only available on Windows.
    /// Using this class, you alleviate the difficult problem of explicitly generating, storing and managing a cryptographic key.
    /// </summary>
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

            return ProtectedData.Protect(data, _configuration.OptionalEntropy, _configuration.Scope);
        }

        public string EncryptText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            var textBytes = text.ToUTF8Bytes();
            var encryptedTextBytes = EncryptData(textBytes);

            return _encoder.Encode(encryptedTextBytes);
        }

        public byte[] DecryptData(byte[] encryptedData)
        {
            if (encryptedData is null || encryptedData.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(encryptedData));
            }

            return ProtectedData.Unprotect(encryptedData, _configuration.OptionalEntropy, _configuration.Scope);
        }

        public string DecryptText(string encryptedText)
        {
            if (string.IsNullOrWhiteSpace(encryptedText))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encryptedText));
            }

            var encryptedTextBytes = _encoder.Decode(encryptedText);
            var decryptedTextBytes = DecryptData(encryptedTextBytes);

            return decryptedTextBytes.ToUTF8String();
        }

        #endregion Public methods
    }

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

#endif