using AleCGN.Security.Cryptography.DependencyInjection;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20;
using AleCGN.Security.Cryptography.Encryption.Files;
using AleCGN.Security.Cryptography.Encryption.PasswordBased;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Hmac;
using AleCGN.Security.Cryptography.KeyDerivation;
using AleCGN.Security.Cryptography.Signatures;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using Xunit;
using SymmetricKeyHelper = AleCGN.Security.Cryptography.SymmetricKeyHelper;

namespace AleCGN.Security.Cryptography.Tests.DependencyInjection
{
    public class DependencyInjectionTests
    {
        private static ServiceProvider Build(System.Action<AleCGNCryptographyOptions> configure = null)
        {
            var services = new ServiceCollection();

            services.AddAleCGNCryptography(configure);

            return services.BuildServiceProvider();
        }

        [Fact]
        public void AddAleCGNCryptography_ResolvesAllKeylessServices()
        {
            using (var provider = Build())
            {
                Assert.NotNull(provider.GetRequiredService<IEncoder>());
                Assert.NotNull(provider.GetRequiredService<IMD5>());
                Assert.NotNull(provider.GetRequiredService<ISHA1>());
                Assert.NotNull(provider.GetRequiredService<ISHA256>());
                Assert.NotNull(provider.GetRequiredService<ISHA384>());
                Assert.NotNull(provider.GetRequiredService<ISHA512>());
                Assert.NotNull(provider.GetRequiredService<IHMACSHA256>());
                Assert.NotNull(provider.GetRequiredService<ISymmetricKeyHelper>());
                Assert.NotNull(provider.GetRequiredService<IPbkdf2>());
                Assert.NotNull(provider.GetRequiredService<IArgon2id>());
                Assert.NotNull(provider.GetRequiredService<IHkdf>());
                Assert.NotNull(provider.GetRequiredService<IPasswordHasher>());
                Assert.NotNull(provider.GetRequiredService<IAesGcm128>());
                Assert.NotNull(provider.GetRequiredService<IAesGcm192>());
                Assert.NotNull(provider.GetRequiredService<IAesGcm256>());
                Assert.NotNull(provider.GetRequiredService<IChaCha20Poly1305>());
                Assert.NotNull(provider.GetRequiredService<IPasswordBasedEncryption>());
                Assert.NotNull(provider.GetRequiredService<IFileEncryption>());
                Assert.NotNull(provider.GetRequiredService<IRsaKeyPairHelper>());
                Assert.NotNull(provider.GetRequiredService<IEcdsaKeyPairHelper>());
                Assert.NotNull(provider.GetRequiredService<IRsaPssSigner>());
                Assert.NotNull(provider.GetRequiredService<IEcdsaSigner>());
            }
        }

        [Fact]
        public void KeyedAesGcm256_WorksOutOfTheBox()
        {
            var key = new SymmetricKeyHelper(new Base64Encoder()).GenerateSecureRandom256BitKey();

            using (var provider = Build(options => options.AesGcm256Key = key))
            {
                var aes = provider.GetRequiredService<IAesGcm256>();

                Assert.Equal("di test", aes.DecryptText(aes.EncryptText("di test")));
            }
        }

        [Fact]
        public void KeylessAesGcm256_ThrowsUntilKeyIsSet()
        {
            using (var provider = Build())
            {
                var aes = provider.GetRequiredService<IAesGcm256>();

                Assert.Throws<CryptographicException>(() => aes.EncryptText("no key"));

                aes.SetOrUpdateKey(new SymmetricKeyHelper(new Base64Encoder()).GenerateSecureRandom256BitKey());

                Assert.Equal("ok", aes.DecryptText(aes.EncryptText("ok")));
            }
        }

        [Fact]
        public void EncoderKind_IsRespected()
        {
            using (var provider = Build(options => options.Encoder = EncoderKind.Hexadecimal))
            {
                var sha256 = provider.GetRequiredService<ISHA256>();

                Assert.Equal(
                    "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
                    sha256.ComputeTextHash("abc", out _));
            }
        }

        [Fact]
        public void PasswordHasher_UsesConfiguredAlgorithm()
        {
            using (var argon2Provider = Build(options =>
                options.Argon2idConfiguration = new Argon2idConfiguration(1024, 1, 1, 16, 32)))
            {
                Assert.StartsWith("$argon2id$",
                    argon2Provider.GetRequiredService<IPasswordHasher>().HashPassword("pw"));
            }

            using (var pbkdf2Provider = Build(options =>
            {
                options.UsePbkdf2ForPasswordHashing = true;
                options.Pbkdf2Configuration = new Pbkdf2Configuration(
                    Pbkdf2PseudoRandomFunction.HMACSHA256, 1_000, 16, 32);
            }))
            {
                Assert.StartsWith("$pbkdf2-sha256$",
                    pbkdf2Provider.GetRequiredService<IPasswordHasher>().HashPassword("pw"));
            }
        }

        [Fact]
        public void KeyedHmac_WorksOutOfTheBox()
        {
            using (var provider = Build(options => options.HmacKey = new byte[] { 1, 2, 3, 4 }))
            {
                var hmac = provider.GetRequiredService<IHMACSHA256>();
                var mac = hmac.ComputeTextHmac("message", out _);

                Assert.True(hmac.VerifyTextHmac("message", mac));
            }
        }
    }
}
