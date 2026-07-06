using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encryption
{
    public class DataProtectionTests
    {
        private static bool IsWindows
            => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        [Fact]
        public void EncryptDecrypt_Data_Roundtrip()
        {
            if (!IsWindows)
            {
                return; // DPAPI is Windows-only
            }

            var dataProtection = new DataProtection(new Base64Encoder(), DataProtectionConfiguration.Default);
            var data = Utf8("local secret");

            Assert.Equal(data, dataProtection.DecryptData(dataProtection.EncryptData(data)));
        }

        [Fact]
        public void EncryptDecrypt_Text_Roundtrip_CurrentUserScope()
        {
            if (!IsWindows)
            {
                return;
            }

            var configuration = new DataProtectionConfiguration(optionalEntropy: null, DataProtectionScope.CurrentUser);
            var dataProtection = new DataProtection(new Base64Encoder(), configuration);
            var encrypted = dataProtection.EncryptText("connection string");

            Assert.Equal("connection string", dataProtection.DecryptText(encrypted));
        }

        [Fact]
        public void Decrypt_WithDifferentEntropy_Fails()
        {
            if (!IsWindows)
            {
                return;
            }

            var encoder = new Base64Encoder();
            var withEntropy = new DataProtection(encoder, new DataProtectionConfiguration(Utf8("entropy-1"), DataProtectionScope.CurrentUser));
            var withOtherEntropy = new DataProtection(encoder, new DataProtectionConfiguration(Utf8("entropy-2"), DataProtectionScope.CurrentUser));
            var encrypted = withEntropy.EncryptData(Utf8("secret"));

            Assert.ThrowsAny<CryptographicException>(() => withOtherEntropy.DecryptData(encrypted));
        }
    }
}
