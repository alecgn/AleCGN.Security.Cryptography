using AleCGN.Security.Cryptography;
using AleCGN.Security.Cryptography.DependencyInjection;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Rsa;
using AleCGN.Security.Cryptography.Encryption.Files;
using AleCGN.Security.Cryptography.Encryption.PasswordBased;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Hmac;
using AleCGN.Security.Cryptography.KeyDerivation;
using AleCGN.Security.Cryptography.Signatures;
using Microsoft.Extensions.DependencyInjection;

namespace ConsoleApp_Net8
{
    internal class Program
    {
        private static int _failures;

        static async Task<int> Main()
        {
            IEncoder hexadecimalEncoder = new HexadecimalEncoder();
            IEncoder base64Encoder = new Base64Encoder();

            // ---------- Encoders ----------
            Check("Hex encode", hexadecimalEncoder.Encode("abc") == "616263");
            Check("Hex decode roundtrip", hexadecimalEncoder.Decode("0x616263").SequenceEqual("abc"u8.ToArray()));
            Check("Base64 roundtrip", base64Encoder.Decode(base64Encoder.Encode("AleCGN")).SequenceEqual("AleCGN"u8.ToArray()));

            var base64UrlEncoder = new Base64UrlEncoder();
            var trickyBytes = new byte[] { 0xFB, 0xEF, 0xBE, 0xFF, 0xFE, 0x3F };
            var base64Url = base64UrlEncoder.Encode(trickyBytes);

            Check("Base64Url is URL-safe", !base64Url.Contains('+') && !base64Url.Contains('/') && !base64Url.Contains('='));
            Check("Base64Url roundtrip", base64UrlEncoder.Decode(base64Url).SequenceEqual(trickyBytes));

            var base32Encoder = new Base32Encoder();

            Check("Base32 RFC 4648 vector", base32Encoder.Encode("foobar") == "MZXW6YTBOI======");
            Check("Base32 roundtrip (lowercase, unpadded)", base32Encoder.Decode("mzxw6ytboi").SequenceEqual("foobar"u8.ToArray()));

            // ---------- Hash ----------
            using var md5 = new MD5(hexadecimalEncoder);
            using var sha256 = new SHA256(hexadecimalEncoder);

            Check("MD5(\"abc\")", md5.ComputeTextHash("abc", out _) == "900150983CD24FB0D6963F7D28E17F72");
            Check("SHA256(\"abc\")", sha256.ComputeTextHash("abc", out _) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
            Check("VerifyTextHash (match)", sha256.VerifyTextHash("abc", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
            Check("VerifyTextHash (mismatch)", !sha256.VerifyTextHash("abcd", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));

            var filePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-hash.txt");
            File.WriteAllText(filePath, "abc");

            Check("File hash", md5.ComputeFileHash(filePath, out _) == "900150983CD24FB0D6963F7D28E17F72");

            var asyncHashResult = await sha256.ComputeFileHashAsync(filePath, progress: new Progress<int>());

            Check("File hash async", asyncHashResult.EncodedHash == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

            var emptyFilePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-empty.txt");
            File.WriteAllText(emptyFilePath, string.Empty);

            Check("Empty file hash", md5.ComputeFileHash(emptyFilePath, out _) == "D41D8CD98F00B204E9800998ECF8427E");

            // ---------- HMAC (RFC 4231 test case 2) ----------
            using var hmacSha256 = new AleCGN.Security.Cryptography.Hmac.HMACSHA256(hexadecimalEncoder, "Jefe"u8.ToArray());
            var hmacVector = hmacSha256.ComputeTextHmac("what do ya want for nothing?", out _);

            Check("HMAC-SHA256 RFC 4231 vector", hmacVector == "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843");
            Check("VerifyTextHmac (match)", hmacSha256.VerifyTextHmac("what do ya want for nothing?", hmacVector));
            Check("VerifyTextHmac (mismatch)", !hmacSha256.VerifyTextHmac("tampered message", hmacVector));

            var fileHmacResult = await hmacSha256.ComputeFileHmacAsync(filePath);

            Check("File HMAC sync == async", hmacSha256.ComputeFileHmac(filePath, out _) == fileHmacResult.EncodedHash);

            // ---------- PBKDF2 (RFC 6070 / known vectors) ----------
            var pbkdf2Sha1 = new Pbkdf2(
                hexadecimalEncoder,
                new Pbkdf2Configuration(Pbkdf2PseudoRandomFunction.HMACSHA1, iterations: 1, saltSize: 16, derivedKeySize: 20));

            Check("PBKDF2-HMAC-SHA1 (RFC 6070 vector)",
                hexadecimalEncoder.Encode(pbkdf2Sha1.DeriveKey("password"u8.ToArray(), "salt"u8.ToArray())) == "0C60C80F961F0E71F3A9B524AF6012062FE037A6");

            // ---------- HKDF (RFC 5869 test case 1) ----------
            var hkdf = new Hkdf(hexadecimalEncoder);
            var hkdfOutput = hkdf.DeriveKey(
                inputKeyMaterial: Enumerable.Repeat((byte)0x0B, 22).ToArray(),
                derivedKeySize: 42,
                salt: hexadecimalEncoder.Decode("000102030405060708090a0b0c"),
                info: hexadecimalEncoder.Decode("f0f1f2f3f4f5f6f7f8f9"));

            Check("HKDF-SHA256 RFC 5869 vector",
                hexadecimalEncoder.Encode(hkdfOutput) == "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865");

            // ---------- Argon2id ----------
            var argon2id = new Argon2id(base64Encoder);
            var argon2Key = argon2id.DeriveTextKey("my password", out var argon2Salt);

            Check("Argon2id verify (match)", argon2id.VerifyTextKey("my password", argon2Salt, argon2Key));
            Check("Argon2id verify (mismatch)", !argon2id.VerifyTextKey("wrong password", argon2Salt, argon2Key));

            // ---------- PasswordHasher (PHC format) ----------
            IPasswordHasher argon2Hasher = new PasswordHasher();
            var phcHash = argon2Hasher.HashPassword("S3cur3!");

            Check("PasswordHasher PHC format", phcHash.StartsWith("$argon2id$v=19$"));
            Check("PasswordHasher verify (match)", argon2Hasher.VerifyPassword("S3cur3!", phcHash));
            Check("PasswordHasher verify (mismatch)", !argon2Hasher.VerifyPassword("wrong", phcHash));
            Check("PasswordHasher NeedsRehash (same config)", !argon2Hasher.NeedsRehash(phcHash));

            IPasswordHasher pbkdf2Hasher = new PasswordHasher(new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 10_000, saltSize: 16, derivedKeySize: 32));
            var pbkdf2PhcHash = pbkdf2Hasher.HashPassword("S3cur3!");

            Check("PasswordHasher PBKDF2 PHC format", pbkdf2PhcHash.StartsWith("$pbkdf2-sha256$i=10000$"));
            Check("PasswordHasher cross-algorithm verify", pbkdf2Hasher.VerifyPassword("S3cur3!", phcHash));
            Check("PasswordHasher NeedsRehash (different algorithm)", pbkdf2Hasher.NeedsRehash(phcHash));

            // ---------- AES-GCM with associated data ----------
            var keyHelper = new SymmetricKeyHelper(base64Encoder);

            using (IAesGcm256 aesGcm256 = new AesGcm256(base64Encoder, keyHelper.GenerateSecureRandom256BitKey()))
            {
                var associatedData = "user:42"u8.ToArray();
                var encryptedWithAad = aesGcm256.EncryptData("payload"u8.ToArray(), associatedData);

                Check("AES-GCM AAD roundtrip", aesGcm256.DecryptData(encryptedWithAad, associatedData).SequenceEqual("payload"u8.ToArray()));
                Check("AES-GCM wrong AAD rejected", Throws(() => aesGcm256.DecryptData(encryptedWithAad, "user:43"u8.ToArray())));

                // ---------- File encryption (chunked) ----------
                var plainFilePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-plain.bin");
                var encryptedFilePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-encrypted.bin");
                var decryptedFilePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-decrypted.bin");
                var randomContent = new byte[10_000]; // ~2.5 chunks of 4 KB

                Random.Shared.NextBytes(randomContent);
                File.WriteAllBytes(plainFilePath, randomContent);

                IFileEncryption fileEncryption = new FileEncryption(aesGcm256, chunkSizeInKB: 4);

                fileEncryption.EncryptFile(plainFilePath, encryptedFilePath);
                fileEncryption.DecryptFile(encryptedFilePath, decryptedFilePath);

                Check("File encryption roundtrip (sync)", File.ReadAllBytes(decryptedFilePath).SequenceEqual(randomContent));

                await fileEncryption.EncryptFileAsync(plainFilePath, encryptedFilePath, new Progress<int>());
                await fileEncryption.DecryptFileAsync(encryptedFilePath, decryptedFilePath, new Progress<int>());

                Check("File encryption roundtrip (async)", File.ReadAllBytes(decryptedFilePath).SequenceEqual(randomContent));

                // Truncate the last chunk: decryption must fail (anti-truncation via AAD).
                var encryptedBytes = File.ReadAllBytes(encryptedFilePath);

                File.WriteAllBytes(encryptedFilePath, encryptedBytes.AsSpan(0, encryptedBytes.Length - 100).ToArray());

                Check("File encryption truncation rejected", Throws(() => fileEncryption.DecryptFile(encryptedFilePath, decryptedFilePath)));
            }

            // ---------- ChaCha20-Poly1305 ----------
            using (var chaCha = new ChaCha20Poly1305(base64Encoder, keyHelper.GenerateSecureRandom256BitKey()))
            {
                var encryptedText = chaCha.EncryptText("chacha secret", "context"u8.ToArray());

                Check("ChaCha20-Poly1305 roundtrip", chaCha.DecryptText(encryptedText, "context"u8.ToArray()) == "chacha secret");
                Check("ChaCha20-Poly1305 wrong AAD rejected", Throws(() => chaCha.DecryptText(encryptedText, "other"u8.ToArray())));

                var tampered = base64Encoder.Decode(encryptedText);
                tampered[0] ^= 0xFF;

                Check("ChaCha20-Poly1305 tampering rejected", Throws(() => chaCha.DecryptData(tampered, "context"u8.ToArray())));
            }

            // ---------- Password-based encryption ----------
            IPasswordBasedEncryption pbe = new PasswordBasedEncryption(base64Encoder, new Pbkdf2Configuration(
                Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 10_000, saltSize: 16, derivedKeySize: 32));
            var pbeEncrypted = pbe.EncryptText("password-protected secret", "correct horse battery staple");

            Check("PBE roundtrip", pbe.DecryptText(pbeEncrypted, "correct horse battery staple") == "password-protected secret");
            Check("PBE wrong password rejected", Throws(() => pbe.DecryptText(pbeEncrypted, "wrong password")));

            // ---------- RSA-OAEP + RSA-PSS ----------
            var rsaKeyPair = new RsaKeyPairHelper().GenerateKeyPair();
            var rsa = new RsaOaepEncryption(base64Encoder, rsaKeyPair.PublicKeyPem, rsaKeyPair.PrivateKeyPem);
            var rsaEncrypted = rsa.EncryptText("small secret");

            Check("RSA-OAEP roundtrip", rsa.DecryptText(rsaEncrypted) == "small secret");

            var rsaSigner = new RsaPssSigner(base64Encoder, rsaKeyPair.PrivateKeyPem, rsaKeyPair.PublicKeyPem);
            var rsaSignature = rsaSigner.SignText("important document");

            Check("RSA-PSS sign/verify", rsaSigner.VerifyTextSignature("important document", rsaSignature));
            Check("RSA-PSS tampered document rejected", !rsaSigner.VerifyTextSignature("tampered document", rsaSignature));

            // ---------- ECDSA ----------
            var ecdsaKeyPair = new EcdsaKeyPairHelper().GenerateKeyPair(EcdsaCurves.NistP256);
            var ecdsaSigner = new EcdsaSigner(base64Encoder, ecdsaKeyPair.PrivateKeyPem, ecdsaKeyPair.PublicKeyPem);
            var ecdsaSignature = ecdsaSigner.SignText("important document");

            Check("ECDSA sign/verify", ecdsaSigner.VerifyTextSignature("important document", ecdsaSignature));
            Check("ECDSA tampered document rejected", !ecdsaSigner.VerifyTextSignature("tampered document", ecdsaSignature));

            // ---------- Dependency injection ----------
            var services = new ServiceCollection();

            services.AddAleCGNCryptography(options =>
            {
                options.AesGcm256Key = keyHelper.GenerateSecureRandom256BitKey();
                options.Pbkdf2Configuration = new Pbkdf2Configuration(
                    Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 10_000, saltSize: 16, derivedKeySize: 32);
            });

            using (var serviceProvider = services.BuildServiceProvider())
            {
                var injectedAes = serviceProvider.GetRequiredService<IAesGcm256>();
                var injectedHasher = serviceProvider.GetRequiredService<IPasswordHasher>();
                var injectedSha256 = serviceProvider.GetRequiredService<ISHA256>();

                Check("DI: AES-GCM resolved and keyed", injectedAes.DecryptText(injectedAes.EncryptText("di test")) == "di test");
                Check("DI: PasswordHasher resolved", injectedHasher.VerifyPassword("pw", injectedHasher.HashPassword("pw")));
                Check("DI: SHA256 resolved", injectedSha256.ComputeTextHash("abc", out _).Length > 0);
            }

            Console.WriteLine(_failures == 0 ? "All checks passed." : $"{_failures} check(s) FAILED.");

            return _failures;
        }

        private static void Check(string description, bool passed)
        {
            if (!passed)
            {
                _failures++;
            }

            Console.WriteLine($"[{(passed ? "PASS" : "FAIL")}] {description}");
        }

        private static bool Throws(Action action)
        {
            try
            {
                action();
                return false;
            }
            catch
            {
                return true;
            }
        }
    }
}
