using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Hmac;
using System;
using System.Threading.Tasks;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;
using CryptographicException = System.Security.Cryptography.CryptographicException;
using HMACMD5 = AleCGN.Security.Cryptography.Hmac.HMACMD5;
using HMACSHA1 = AleCGN.Security.Cryptography.Hmac.HMACSHA1;
using HMACSHA256 = AleCGN.Security.Cryptography.Hmac.HMACSHA256;
using HMACSHA384 = AleCGN.Security.Cryptography.Hmac.HMACSHA384;
using HMACSHA512 = AleCGN.Security.Cryptography.Hmac.HMACSHA512;

namespace AleCGN.Security.Cryptography.Tests.Hmac
{
    public class HmacTests
    {
        private static readonly HexadecimalEncoder _hexEncoder = new HexadecimalEncoder();
        private const string _rfcMessage = "what do ya want for nothing?";

        private static IHmac CreateHmac(HashAlgorithmKind kind, byte[] key)
        {
            switch (kind)
            {
                case HashAlgorithmKind.MD5: return new HMACMD5(_hexEncoder, key);
                case HashAlgorithmKind.SHA1: return new HMACSHA1(_hexEncoder, key);
                case HashAlgorithmKind.SHA256: return new HMACSHA256(_hexEncoder, key);
                case HashAlgorithmKind.SHA384: return new HMACSHA384(_hexEncoder, key);
                case HashAlgorithmKind.SHA512: return new HMACSHA512(_hexEncoder, key);
                default: throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        // RFC 2202 (MD5/SHA1) and RFC 4231 test case 2 (SHA2 family): key = "Jefe"
        [Theory]
        [InlineData(HashAlgorithmKind.MD5, "750C783E6AB0B503EAA86E310A5DB738")]
        [InlineData(HashAlgorithmKind.SHA1, "EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79")]
        [InlineData(HashAlgorithmKind.SHA256, "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843")]
        [InlineData(HashAlgorithmKind.SHA384, "AF45D2E376484031617F78D2B58A6B1B9C7EF464F5A01B47E42EC3736322445E8E2240CA5E69E2C78B3239ECFAB21649")]
        [InlineData(HashAlgorithmKind.SHA512, "164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737")]
        public void ComputeTextHmac_OfficialVectors(HashAlgorithmKind kind, string expected)
        {
            using (var hmac = CreateHmac(kind, Utf8("Jefe")))
            {
                Assert.Equal(expected, hmac.ComputeTextHmac(_rfcMessage, out _));
            }
        }

        [Fact]
        public void VerifyHmac_MatchAndMismatch()
        {
            using (var hmac = new HMACSHA256(_hexEncoder, Utf8("Jefe")))
            {
                var mac = hmac.ComputeTextHmac(_rfcMessage, out var raw);

                Assert.True(hmac.VerifyTextHmac(_rfcMessage, mac));
                Assert.False(hmac.VerifyTextHmac("tampered", mac));
                Assert.True(hmac.VerifyHmac(Utf8(_rfcMessage), raw));

                raw[0] ^= 0xFF;

                Assert.False(hmac.VerifyHmac(Utf8(_rfcMessage), raw));
            }
        }

        [Fact]
        public void SetOrUpdateKey_ChangesResult()
        {
            using (var hmac = new HMACSHA256(_hexEncoder, Utf8("key-1")))
            {
                var mac1 = hmac.ComputeTextHmac("message", out _);

                hmac.SetOrUpdateKey(Utf8("key-2"));

                Assert.NotEqual(mac1, hmac.ComputeTextHmac("message", out _));
            }
        }

        [Fact]
        public void ComputeHmac_WithoutKey_Throws()
        {
            using (var hmac = new HMACSHA256(_hexEncoder))
            {
                Assert.Throws<CryptographicException>(() => hmac.ComputeTextHmac("message", out _));
            }
        }

        [Fact]
        public void DefensiveKeyCopy_CallerMutationDoesNotAffectInstance()
        {
            var key = Utf8("original-key-bytes");

            using (var hmac = new HMACSHA256(_hexEncoder, key))
            {
                var before = hmac.ComputeTextHmac("message", out _);

                key[0] ^= 0xFF;

                Assert.Equal(before, hmac.ComputeTextHmac("message", out _));
            }
        }

        [Fact]
        public async Task ComputeFileHmac_SyncEqualsAsync_AndMatchesInMemory()
        {
            var content = new byte[150_000];

            new Random(3).NextBytes(content);

            var filePath = CreateTempFile(content);

            try
            {
                using (var hmac = new HMACSHA256(_hexEncoder, Utf8("file-key")))
                {
                    var inMemory = hmac.ComputeHmac(content, out _);
                    var syncFile = hmac.ComputeFileHmac(filePath, out _);
                    var asyncResult = await hmac.ComputeFileHmacAsync(filePath);

                    Assert.Equal(inMemory, syncFile);
                    Assert.Equal(inMemory, asyncResult.EncodedHash);
                    Assert.True(hmac.VerifyFileHmac(filePath, syncFile));
                    Assert.False(hmac.VerifyFileHmac(filePath, inMemory.Replace(inMemory[0], inMemory[0] == 'A' ? 'B' : 'A')));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        [Fact]
        public void EncodedKeyConstructor_EquivalentToRawKey()
        {
            var key = Utf8("Jefe");

            using (var fromRaw = new HMACSHA256(_hexEncoder, key))
            using (var fromEncoded = new HMACSHA256(_hexEncoder, _hexEncoder.Encode(key)))
            {
                Assert.Equal(
                    fromRaw.ComputeTextHmac(_rfcMessage, out _),
                    fromEncoded.ComputeTextHmac(_rfcMessage, out _));
            }
        }
    }
}
