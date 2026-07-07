using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Rsa;
using AleCGN.Security.Cryptography.Encryption.Files;
using AleCGN.Security.Cryptography.Encryption.PasswordBased;
using AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Hmac;
using AleCGN.Security.Cryptography.KeyDerivation;
using AleCGN.Security.Cryptography.Signatures;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace AleCGN.Security.Cryptography.DependencyInjection
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers all AleCGN.Security.Cryptography services as singletons.
        /// Keyed services (AES-GCM, ChaCha20-Poly1305, HMAC, RSA, ECDSA) are registered with the keys
        /// provided via <see cref="AleCGNCryptographyOptions"/> when available; otherwise they are
        /// registered keyless and SetOrUpdateKey(...) must be called before use.
        /// </summary>
        public static IServiceCollection AddAleCGNCryptography(
            this IServiceCollection services,
            Action<AleCGNCryptographyOptions> configureOptions = null)
        {
            if (services is null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            var options = new AleCGNCryptographyOptions();

            configureOptions?.Invoke(options);

            services.AddSingleton<IEncoder>(_ => CreateEncoder(options.Encoder));

            AddHashes(services);
            AddHmacs(services, options);
            AddKeyDerivation(services, options);
            AddSymmetricEncryption(services, options);
            AddAsymmetric(services, options);

            return services;
        }

        private static IEncoder CreateEncoder(EncoderKind encoderKind)
        {
            switch (encoderKind)
            {
                case EncoderKind.Base64:
                    return new Base64Encoder();
                case EncoderKind.Base64Url:
                    return new Base64UrlEncoder();
                case EncoderKind.Base32:
                    return new Base32Encoder();
                case EncoderKind.Hexadecimal:
                    return new HexadecimalEncoder();
                default:
                    throw new ArgumentOutOfRangeException(nameof(encoderKind));
            }
        }

        private static void AddHashes(IServiceCollection services)
        {
            services.AddSingleton<IMD5, MD5>();
            services.AddSingleton<ISHA1, SHA1>();
            services.AddSingleton<ISHA256, SHA256>();
            services.AddSingleton<ISHA384, SHA384>();
            services.AddSingleton<ISHA512, SHA512>();
        }

        private static void AddHmacs(IServiceCollection services, AleCGNCryptographyOptions options)
        {
            services.AddSingleton<IHMACMD5>(serviceProvider => CreateHmac(
                new HMACMD5(serviceProvider.GetRequiredService<IEncoder>()), options.HmacKey));
            services.AddSingleton<IHMACSHA1>(serviceProvider => CreateHmac(
                new HMACSHA1(serviceProvider.GetRequiredService<IEncoder>()), options.HmacKey));
            services.AddSingleton<IHMACSHA256>(serviceProvider => CreateHmac(
                new HMACSHA256(serviceProvider.GetRequiredService<IEncoder>()), options.HmacKey));
            services.AddSingleton<IHMACSHA384>(serviceProvider => CreateHmac(
                new HMACSHA384(serviceProvider.GetRequiredService<IEncoder>()), options.HmacKey));
            services.AddSingleton<IHMACSHA512>(serviceProvider => CreateHmac(
                new HMACSHA512(serviceProvider.GetRequiredService<IEncoder>()), options.HmacKey));
        }

        private static THmac CreateHmac<THmac>(THmac hmac, byte[] key) where THmac : IHmac
        {
            if (key != null)
            {
                hmac.SetOrUpdateKey(key);
            }

            return hmac;
        }

        private static void AddKeyDerivation(IServiceCollection services, AleCGNCryptographyOptions options)
        {
            services.AddSingleton<ISymmetricKeyHelper, SymmetricKeyHelper>();
            services.AddSingleton<IPbkdf2>(serviceProvider => new Pbkdf2(
                serviceProvider.GetRequiredService<IEncoder>(), options.Pbkdf2Configuration));
            services.AddSingleton<IArgon2id>(serviceProvider => new Argon2id(
                serviceProvider.GetRequiredService<IEncoder>(), options.Argon2idConfiguration));
            services.AddSingleton<IHkdf, Hkdf>();
            services.AddSingleton<IPasswordHasher>(_ => options.UsePbkdf2ForPasswordHashing
                ? new PasswordHasher(options.Pbkdf2Configuration)
                : new PasswordHasher(options.Argon2idConfiguration));
        }

        private static void AddSymmetricEncryption(IServiceCollection services, AleCGNCryptographyOptions options)
        {
            services.AddSingleton<IAesGcm128>(serviceProvider => options.AesGcm128Key is null
                ? new AesGcm128(serviceProvider.GetRequiredService<IEncoder>())
                : new AesGcm128(serviceProvider.GetRequiredService<IEncoder>(), options.AesGcm128Key));
            services.AddSingleton<IAesGcm192>(serviceProvider => options.AesGcm192Key is null
                ? new AesGcm192(serviceProvider.GetRequiredService<IEncoder>())
                : new AesGcm192(serviceProvider.GetRequiredService<IEncoder>(), options.AesGcm192Key));
            services.AddSingleton<IAesGcm256>(serviceProvider => options.AesGcm256Key is null
                ? new AesGcm256(serviceProvider.GetRequiredService<IEncoder>())
                : new AesGcm256(serviceProvider.GetRequiredService<IEncoder>(), options.AesGcm256Key));
            services.AddSingleton<IChaCha20Poly1305>(serviceProvider => options.ChaCha20Poly1305Key is null
                ? new ChaCha20Poly1305(serviceProvider.GetRequiredService<IEncoder>())
                : new ChaCha20Poly1305(serviceProvider.GetRequiredService<IEncoder>(), options.ChaCha20Poly1305Key));

            services.AddSingleton<IPasswordBasedEncryption>(serviceProvider => new PasswordBasedEncryption(
                serviceProvider.GetRequiredService<IEncoder>(), options.Pbkdf2Configuration));
            services.AddSingleton<IFileEncryption>(serviceProvider => new FileEncryption(
                serviceProvider.GetRequiredService<IAesGcm256>(), options.FileEncryptionChunkSizeInKB));

            if (options.DataProtectionConfiguration != null)
            {
#pragma warning disable CA1416 // Registration is opt-in via options and only valid on Windows.
                services.AddSingleton<IDataProtection>(serviceProvider => new DataProtection(
                    serviceProvider.GetRequiredService<IEncoder>(), options.DataProtectionConfiguration));
#pragma warning restore CA1416
            }
        }

        private static void AddAsymmetric(IServiceCollection services, AleCGNCryptographyOptions options)
        {
            services.AddSingleton<IRsaKeyPairHelper, RsaKeyPairHelper>();
            services.AddSingleton<IEcdsaKeyPairHelper, EcdsaKeyPairHelper>();

            services.AddSingleton<IRsaOaepEncryption>(serviceProvider => new RsaOaepEncryption(
                serviceProvider.GetRequiredService<IEncoder>(), options.RsaPublicKeyPem, options.RsaPrivateKeyPem));
            services.AddSingleton<IRsaPssSigner>(serviceProvider => new RsaPssSigner(
                serviceProvider.GetRequiredService<IEncoder>(), options.RsaPrivateKeyPem, options.RsaPublicKeyPem));
            services.AddSingleton<IEcdsaSigner>(serviceProvider => new EcdsaSigner(
                serviceProvider.GetRequiredService<IEncoder>(), options.EcdsaPrivateKeyPem, options.EcdsaPublicKeyPem));
        }
    }
}
