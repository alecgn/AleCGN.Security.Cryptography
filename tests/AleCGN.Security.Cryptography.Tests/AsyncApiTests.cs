using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Rsa;
using AleCGN.Security.Cryptography.Encryption.PasswordBased;
using AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.KeyDerivation;
using AleCGN.Security.Cryptography.Signatures;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;
using ChaCha20Poly1305 = AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20.ChaCha20Poly1305;
using HMACSHA256 = AleCGN.Security.Cryptography.Hmac.HMACSHA256;

namespace AleCGN.Security.Cryptography.Tests
{
    public class AsyncApiTests
    {
        private static readonly HexadecimalEncoder _hexEncoder = new HexadecimalEncoder();
        private static readonly Base64Encoder _base64Encoder = new Base64Encoder();
        private static readonly SymmetricKeyHelper _keyHelper = new SymmetricKeyHelper(_base64Encoder);

        #region Hash

        [Fact]
        public async Task ComputeHashAsync_MatchesSyncAndVector()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                var result = await sha256.ComputeHashAsync(Utf8("abc"));

                Assert.Equal("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", result.EncodedHash);
                Assert.Equal(result.EncodedHash, _hexEncoder.Encode(result.HashBytes));
            }
        }

        [Fact]
        public async Task ComputeTextHashAsync_SupportsOffsetAndCount()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                var full = await sha256.ComputeTextHashAsync("abc");
                var sliced = await sha256.ComputeTextHashAsync("XXabc", offset: 2);

                Assert.Equal(full.EncodedHash, sliced.EncodedHash);
            }
        }

        [Fact]
        public async Task VerifyHashAsync_And_VerifyTextHashAsync()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                var result = await sha256.ComputeTextHashAsync("abc");

                Assert.True(await sha256.VerifyTextHashAsync("abc", result.EncodedHash));
                Assert.False(await sha256.VerifyTextHashAsync("abcd", result.EncodedHash));
                Assert.True(await sha256.VerifyHashAsync(Utf8("abc"), result.HashBytes));
                Assert.False(await sha256.VerifyHashAsync(Utf8("abd"), result.HashBytes));
            }
        }

        [Fact]
        public async Task VerifyFileHashAsync_BothOverloads()
        {
            var filePath = CreateTempFile("abc");

            try
            {
                using (var sha256 = new SHA256(_hexEncoder))
                {
                    var result = await sha256.ComputeFileHashAsync(filePath);

                    Assert.True(await sha256.VerifyFileHashAsync(filePath, result.HashBytes));
                    Assert.True(await sha256.VerifyFileHashAsync(filePath, result.EncodedHash, progress: new Progress<int>()));
                    Assert.False(await sha256.VerifyFileHashAsync(filePath, new byte[32]));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        #endregion Hash


        #region HMAC

        [Fact]
        public async Task HmacAsyncApis_MatchSync()
        {
            using (var hmac = new HMACSHA256(_hexEncoder, Utf8("Jefe")))
            {
                var sync = hmac.ComputeTextHmac("what do ya want for nothing?", out _);
                var asyncResult = await hmac.ComputeTextHmacAsync("what do ya want for nothing?");

                Assert.Equal(sync, asyncResult.EncodedHash);
                Assert.True(await hmac.VerifyTextHmacAsync("what do ya want for nothing?", sync));
                Assert.False(await hmac.VerifyTextHmacAsync("tampered", sync));

                var dataResult = await hmac.ComputeHmacAsync(Utf8("payload"));

                Assert.True(await hmac.VerifyHmacAsync(Utf8("payload"), dataResult.HashBytes));
            }
        }

        [Fact]
        public async Task VerifyFileHmacAsync_BothOverloads()
        {
            var filePath = CreateTempFile("file content");

            try
            {
                using (var hmac = new HMACSHA256(_hexEncoder, Utf8("file-key")))
                {
                    var result = await hmac.ComputeFileHmacAsync(filePath);

                    Assert.True(await hmac.VerifyFileHmacAsync(filePath, result.HashBytes));
                    Assert.True(await hmac.VerifyFileHmacAsync(filePath, result.EncodedHash));
                    Assert.False(await hmac.VerifyFileHmacAsync(filePath, new byte[32]));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        #endregion HMAC


        #region Key derivation

        [Fact]
        public async Task Pbkdf2Async_MatchesRfc6070Vector_AndResultTypes()
        {
            var pbkdf2 = new Pbkdf2(_hexEncoder, new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA1, iterations: 1, saltSize: 16, derivedKeySize: 20));

            var derivedKey = await pbkdf2.DeriveKeyAsync(Utf8("password"), Utf8("salt"));

            Assert.Equal("0C60C80F961F0E71F3A9B524AF6012062FE037A6", _hexEncoder.Encode(derivedKey));

            var result = await pbkdf2.DeriveKeyAsync(Utf8("password"));

            Assert.Equal(16, result.Salt.Length);
            Assert.True(await pbkdf2.VerifyKeyAsync(Utf8("password"), result.Salt, result.Key));
            Assert.False(await pbkdf2.VerifyKeyAsync(Utf8("wrong"), result.Salt, result.Key));

            var textResult = await pbkdf2.DeriveTextKeyAsync("password");

            Assert.True(await pbkdf2.VerifyTextKeyAsync("password", textResult.EncodedSalt, textResult.EncodedKey));
            Assert.Equal(
                textResult.EncodedKey,
                await pbkdf2.DeriveTextKeyAsync("password", textResult.EncodedSalt));
        }

        [Fact]
        public async Task Argon2idAsync_RoundtripAndVerify()
        {
            var argon2 = new Argon2id(_hexEncoder, new Argon2idConfiguration(1024, 1, 1, 16, 32));
            var result = await argon2.DeriveKeyAsync(Utf8("password"));

            Assert.True(await argon2.VerifyKeyAsync(Utf8("password"), result.Salt, result.Key));

            var textResult = await argon2.DeriveTextKeyAsync("password");

            Assert.True(await argon2.VerifyTextKeyAsync("password", textResult.EncodedSalt, textResult.EncodedKey));
            Assert.False(await argon2.VerifyTextKeyAsync("wrong", textResult.EncodedSalt, textResult.EncodedKey));
        }

        [Fact]
        public async Task HkdfAsync_MatchesRfc5869Vector()
        {
            var hkdf = new Hkdf(_hexEncoder);
            var okm = await hkdf.DeriveKeyAsync(
                RepeatedBytes(0x0B, 22),
                42,
                _hexEncoder.Decode("000102030405060708090a0b0c"),
                _hexEncoder.Decode("f0f1f2f3f4f5f6f7f8f9"));

            Assert.Equal(
                "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865",
                _hexEncoder.Encode(okm));

            Assert.Equal(
                await hkdf.DeriveTextKeyAsync("master", 32, "salt", "info"),
                hkdf.DeriveTextKey("master", 32, "salt", "info"));
        }

        [Fact]
        public async Task PasswordHasherAsync_HashVerifyAndNeedsRehash()
        {
            var hasher = new PasswordHasher(new Argon2idConfiguration(1024, 1, 1, 16, 32));
            var hash = await hasher.HashPasswordAsync("S3cur3!");

            Assert.StartsWith("$argon2id$", hash);
            Assert.True(await hasher.VerifyPasswordAsync("S3cur3!", hash));
            Assert.False(await hasher.VerifyPasswordAsync("wrong", hash));
            Assert.False(await hasher.NeedsRehashAsync(hash));

            var otherHasher = new PasswordHasher(new Argon2idConfiguration(2048, 1, 1, 16, 32));

            Assert.True(await otherHasher.NeedsRehashAsync(hash));
        }

        #endregion Key derivation


        #region AEAD / encryption

        [Fact]
        public async Task AesGcmAsync_RoundtripWithAndWithoutAad()
        {
            using (IAesGcm256 aes = new AesGcm256(_base64Encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                var encrypted = await aes.EncryptDataAsync(Utf8("payload"));

                Assert.Equal(Utf8("payload"), await aes.DecryptDataAsync(encrypted));

                var withAad = await aes.EncryptDataAsync(Utf8("payload"), Utf8("user:42"));

                Assert.Equal(Utf8("payload"), await aes.DecryptDataAsync(withAad, Utf8("user:42")));
                await Assert.ThrowsAnyAsync<Exception>(() => aes.DecryptDataAsync(withAad, Utf8("user:43")));

                var encryptedText = await aes.EncryptTextAsync("text", Utf8("ctx"));

                Assert.Equal("text", await aes.DecryptTextAsync(encryptedText, Utf8("ctx")));
            }
        }

        [Fact]
        public async Task ChaCha20Poly1305Async_Roundtrip()
        {
            using (var chacha = new ChaCha20Poly1305(_base64Encoder, _keyHelper.GenerateSecureRandom256BitKey()))
            {
                var encrypted = await chacha.EncryptTextAsync("secret", Utf8("ctx"));

                Assert.Equal("secret", await chacha.DecryptTextAsync(encrypted, Utf8("ctx")));
                await Assert.ThrowsAnyAsync<Exception>(() => chacha.DecryptTextAsync(encrypted, Utf8("other")));
            }
        }

        [Fact]
        public async Task PasswordBasedEncryptionAsync_Roundtrip()
        {
            var pbe = new PasswordBasedEncryption(_base64Encoder, new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 1_000, saltSize: 16, derivedKeySize: 32));

            var encryptedData = await pbe.EncryptDataAsync(Utf8("secret"), "password");

            Assert.Equal(Utf8("secret"), await pbe.DecryptDataAsync(encryptedData, "password"));

            var encryptedText = await pbe.EncryptTextAsync("secret text", "password");

            Assert.Equal("secret text", await pbe.DecryptTextAsync(encryptedText, "password"));
            await Assert.ThrowsAnyAsync<Exception>(() => pbe.DecryptTextAsync(encryptedText, "wrong"));
        }

        [Fact]
        public async Task DataProtectionAsync_Roundtrip()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return; // DPAPI is Windows-only
            }

            var dataProtection = new DataProtection(_base64Encoder, DataProtectionConfiguration.Default);
            var encrypted = await dataProtection.EncryptTextAsync("local secret");

            Assert.Equal("local secret", await dataProtection.DecryptTextAsync(encrypted));
        }

        #endregion AEAD / encryption


        #region Asymmetric

        [Fact]
        public async Task RsaOaepAsync_Roundtrip()
        {
            var keyPair = await new RsaKeyPairHelper().GenerateKeyPairAsync();
            var rsa = new RsaOaepEncryption(_base64Encoder, keyPair.PublicKeyPem, keyPair.PrivateKeyPem);
            var encrypted = await rsa.EncryptTextAsync("small secret");

            Assert.Equal("small secret", await rsa.DecryptTextAsync(encrypted));

            var encryptedData = await rsa.EncryptDataAsync(Utf8("bytes"));

            Assert.Equal(Utf8("bytes"), await rsa.DecryptDataAsync(encryptedData));
        }

        [Fact]
        public async Task SignersAsync_SignAndVerify()
        {
            var rsaKeyPair = await new RsaKeyPairHelper().GenerateKeyPairAsync();
            var rsaSigner = new RsaPssSigner(_base64Encoder, rsaKeyPair.PrivateKeyPem, rsaKeyPair.PublicKeyPem);
            var rsaSignature = await rsaSigner.SignTextAsync("document");

            Assert.True(await rsaSigner.VerifyTextSignatureAsync("document", rsaSignature));
            Assert.False(await rsaSigner.VerifyTextSignatureAsync("tampered", rsaSignature));

            var ecdsaKeyPair = await new EcdsaKeyPairHelper().GenerateKeyPairAsync(EcdsaCurves.NistP256);
            var ecdsaSigner = new EcdsaSigner(_base64Encoder, ecdsaKeyPair.PrivateKeyPem, ecdsaKeyPair.PublicKeyPem);
            var ecdsaSignature = await ecdsaSigner.SignDataAsync(Utf8("document"));

            Assert.True(await ecdsaSigner.VerifySignatureAsync(Utf8("document"), ecdsaSignature));
        }

        #endregion Asymmetric


        #region Cancellation

        [Fact]
        public async Task PreCancelledToken_CancelsBeforeExecution()
        {
            using (var cts = new CancellationTokenSource())
            {
                cts.Cancel();

                var pbkdf2 = new Pbkdf2(_base64Encoder);
                var hasher = new PasswordHasher(new Argon2idConfiguration(1024, 1, 1, 16, 32));

                await Assert.ThrowsAnyAsync<OperationCanceledException>(
                    () => pbkdf2.DeriveKeyAsync(Utf8("password"), cancellationToken: cts.Token));
                await Assert.ThrowsAnyAsync<OperationCanceledException>(
                    () => hasher.HashPasswordAsync("password", cts.Token));

                using (var sha256 = new SHA256(_hexEncoder))
                {
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(
                        () => sha256.ComputeHashAsync(Utf8("abc"), cancellationToken: cts.Token));
                }

                using (IAesGcm256 aes = new AesGcm256(_base64Encoder, _keyHelper.GenerateSecureRandom256BitKey()))
                {
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(
                        () => aes.EncryptDataAsync(Utf8("data"), cancellationToken: cts.Token));
                }
            }
        }

        #endregion Cancellation
    }
}
