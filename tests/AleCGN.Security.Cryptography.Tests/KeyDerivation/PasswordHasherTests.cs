using AleCGN.Security.Cryptography.KeyDerivation;
using System;
using Xunit;

namespace AleCGN.Security.Cryptography.Tests.KeyDerivation
{
    public class PasswordHasherTests
    {
        // Low-cost configurations to keep tests fast
        private static readonly Argon2idConfiguration _argon2Config =
            new Argon2idConfiguration(memorySizeInKB: 1024, iterations: 1, parallelism: 1, saltSize: 16, derivedKeySize: 32);
        private static readonly Pbkdf2Configuration _pbkdf2Config =
            new Pbkdf2Configuration(Pbkdf2PseudoRandomFunction.HMACSHA256, iterations: 1_000, saltSize: 16, derivedKeySize: 32);

        [Fact]
        public void HashPassword_Argon2id_ProducesPhcFormat()
        {
            var hasher = new PasswordHasher(_argon2Config);
            var hash = hasher.HashPassword("S3cur3!");

            Assert.StartsWith("$argon2id$v=19$m=1024,t=1,p=1$", hash);
            Assert.Equal(6, hash.Split('$').Length);
        }

        [Fact]
        public void HashPassword_Pbkdf2_ProducesPhcFormat()
        {
            var hasher = new PasswordHasher(_pbkdf2Config);
            var hash = hasher.HashPassword("S3cur3!");

            Assert.StartsWith("$pbkdf2-sha256$i=1000$", hash);
        }

        [Fact]
        public void VerifyPassword_MatchAndMismatch()
        {
            var hasher = new PasswordHasher(_argon2Config);
            var hash = hasher.HashPassword("S3cur3!");

            Assert.True(hasher.VerifyPassword("S3cur3!", hash));
            Assert.False(hasher.VerifyPassword("wrong", hash));
        }

        [Fact]
        public void VerifyPassword_Pbkdf2_MatchAndMismatch()
        {
            var hasher = new PasswordHasher(_pbkdf2Config);
            var hash = hasher.HashPassword("S3cur3!");

            Assert.True(hasher.VerifyPassword("S3cur3!", hash));
            Assert.False(hasher.VerifyPassword("wrong", hash));
        }

        [Fact]
        public void VerifyPassword_IsCrossAlgorithm_HashParametersComeFromTheString()
        {
            var argon2Hasher = new PasswordHasher(_argon2Config);
            var pbkdf2Hasher = new PasswordHasher(_pbkdf2Config);

            var argonHash = argon2Hasher.HashPassword("pw");
            var pbkdf2Hash = pbkdf2Hasher.HashPassword("pw");

            // Each hasher verifies hashes produced by the other, using the embedded parameters
            Assert.True(pbkdf2Hasher.VerifyPassword("pw", argonHash));
            Assert.True(argon2Hasher.VerifyPassword("pw", pbkdf2Hash));
        }

        [Fact]
        public void HashPassword_SamePasswordTwice_ProducesDifferentHashes()
        {
            var hasher = new PasswordHasher(_argon2Config);

            Assert.NotEqual(hasher.HashPassword("pw"), hasher.HashPassword("pw")); // random salt
        }

        [Fact]
        public void NeedsRehash_FalseForCurrentConfiguration()
        {
            var hasher = new PasswordHasher(_argon2Config);

            Assert.False(hasher.NeedsRehash(hasher.HashPassword("pw")));
        }

        [Fact]
        public void NeedsRehash_TrueWhenParametersChange()
        {
            var oldHasher = new PasswordHasher(_argon2Config);
            var newHasher = new PasswordHasher(new Argon2idConfiguration(2048, 1, 1, 16, 32));

            Assert.True(newHasher.NeedsRehash(oldHasher.HashPassword("pw")));
        }

        [Fact]
        public void NeedsRehash_TrueWhenAlgorithmChanges()
        {
            var pbkdf2Hasher = new PasswordHasher(_pbkdf2Config);
            var argon2Hasher = new PasswordHasher(_argon2Config);

            Assert.True(argon2Hasher.NeedsRehash(pbkdf2Hasher.HashPassword("pw")));
            Assert.True(pbkdf2Hasher.NeedsRehash(argon2Hasher.HashPassword("pw")));
        }

        [Theory]
        [InlineData("not-a-phc-string")]
        [InlineData("$unknown$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA")]
        [InlineData("$argon2id$v=18$m=1024,t=1,p=1$c2FsdA$aGFzaA")]  // wrong version
        [InlineData("$argon2id$v=19$m=1024,t=1$c2FsdA$aGFzaA")]      // missing parameter
        [InlineData("$argon2id$v=19$m=0,t=1,p=1$c2FsdA$aGFzaA")]     // invalid value
        [InlineData("$pbkdf2-sha256$i=abc$c2FsdA$aGFzaA")]           // non-numeric iterations
        [InlineData("$pbkdf2-md5$i=1000$c2FsdA$aGFzaA")]             // unsupported PRF
        [InlineData("$argon2id$v=19$m=1024,t=1,p=1$!!$aGFzaA")]      // invalid base64 salt
        public void VerifyPassword_MalformedHash_Throws(string malformed)
        {
            var hasher = new PasswordHasher(_argon2Config);

            Assert.Throws<ArgumentException>(() => hasher.VerifyPassword("pw", malformed));
        }

        [Fact]
        public void Constructors_NullConfiguration_Throw()
        {
            Assert.Throws<ArgumentNullException>(() => new PasswordHasher((Argon2idConfiguration)null));
            Assert.Throws<ArgumentNullException>(() => new PasswordHasher((Pbkdf2Configuration)null));
        }
    }
}
