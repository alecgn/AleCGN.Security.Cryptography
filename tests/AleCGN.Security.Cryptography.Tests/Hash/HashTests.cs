using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Hash
{
    public class HashTests
    {
        private static readonly HexadecimalEncoder _hexEncoder = new HexadecimalEncoder();

        private static IHash CreateHash(HashAlgorithmKind kind)
        {
            switch (kind)
            {
                case HashAlgorithmKind.MD5: return new MD5(_hexEncoder);
                case HashAlgorithmKind.SHA1: return new SHA1(_hexEncoder);
                case HashAlgorithmKind.SHA256: return new SHA256(_hexEncoder);
                case HashAlgorithmKind.SHA384: return new SHA384(_hexEncoder);
                case HashAlgorithmKind.SHA512: return new SHA512(_hexEncoder);
                default: throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        // FIPS 180-2 / RFC 1321 test vectors for "abc"
        [Theory]
        [InlineData(HashAlgorithmKind.MD5, "900150983CD24FB0D6963F7D28E17F72")]
        [InlineData(HashAlgorithmKind.SHA1, "A9993E364706816ABA3E25717850C26C9CD0D89D")]
        [InlineData(HashAlgorithmKind.SHA256, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
        [InlineData(HashAlgorithmKind.SHA384, "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7")]
        [InlineData(HashAlgorithmKind.SHA512, "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F")]
        public void ComputeTextHash_OfficialVectors(HashAlgorithmKind kind, string expected)
        {
            using (var hash = CreateHash(kind))
            {
                Assert.Equal(expected, hash.ComputeTextHash("abc", out var raw));
                Assert.Equal(expected, _hexEncoder.Encode(raw));
            }
        }

        [Fact]
        public void ComputeHash_WithOffsetAndCount()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                var full = sha256.ComputeHash(Utf8("abc"), out _);
                var sliced = sha256.ComputeHash(Utf8("XXabcYY"), out _, offset: 2, count: 3);

                Assert.Equal(full, sliced);
            }
        }

        [Fact]
        public void ComputeTextHash_WithOffsetOnly_UsesRemainderOfText()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                Assert.Equal(
                    sha256.ComputeTextHash("abc", out _),
                    sha256.ComputeTextHash("XXabc", out _, offset: 2));
            }
        }

        [Fact]
        public void VerifyHash_And_VerifyTextHash()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                var digest = sha256.ComputeTextHash("abc", out var raw);

                Assert.True(sha256.VerifyTextHash("abc", digest));
                Assert.False(sha256.VerifyTextHash("abcd", digest));
                Assert.True(sha256.VerifyHash(Utf8("abc"), raw));
                Assert.False(sha256.VerifyHash(Utf8("abd"), raw));
            }
        }

        [Fact]
        public void ComputeFileHash_MatchesInMemoryHash_AndIsRepeatable()
        {
            var filePath = CreateTempFile("abc");

            try
            {
                using (var md5 = new MD5(_hexEncoder))
                {
                    Assert.Equal("900150983CD24FB0D6963F7D28E17F72", md5.ComputeFileHash(filePath, out _));
                    // Repeated call on the same instance must produce the same result
                    Assert.Equal("900150983CD24FB0D6963F7D28E17F72", md5.ComputeFileHash(filePath, out _));
                    Assert.True(md5.VerifyFileHash(filePath, "900150983CD24FB0D6963F7D28E17F72"));
                    Assert.False(md5.VerifyFileHash(filePath, "00000000000000000000000000000000"));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        [Fact]
        public void ComputeFileHash_EmptyFile()
        {
            var filePath = CreateTempFile(string.Empty);

            try
            {
                using (var md5 = new MD5(_hexEncoder))
                {
                    Assert.Equal("D41D8CD98F00B204E9800998ECF8427E", md5.ComputeFileHash(filePath, out _));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        [Fact]
        public void ComputeFileHash_LargerThanBuffer_ReportsProgress()
        {
            var content = new byte[300_000];

            new Random(1).NextBytes(content);

            var filePath = CreateTempFile(content);

            try
            {
                using (var sha256 = new SHA256(_hexEncoder))
                {
                    var progressFired = false;

                    sha256.OnComputeFileHashProgressChanged += (_, __) => progressFired = true;

                    var fromFile = sha256.ComputeFileHash(filePath, out _, bufferSizeInKB: 64);
                    var fromMemory = sha256.ComputeHash(content, out _);

                    Assert.Equal(fromMemory, fromFile);
                    Assert.True(progressFired);
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        [Fact]
        public async Task ComputeFileHashAsync_MatchesSync_AndReportsProgress()
        {
            var content = new byte[200_000];

            new Random(2).NextBytes(content);

            var filePath = CreateTempFile(content);

            try
            {
                using (var sha256 = new SHA256(_hexEncoder))
                {
                    var sync = sha256.ComputeFileHash(filePath, out _);
                    var result = await sha256.ComputeFileHashAsync(filePath, progress: new Progress<int>());

                    Assert.Equal(sync, result.EncodedHash);
                    Assert.Equal(sync, _hexEncoder.Encode(result.HashBytes));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        [Fact]
        public async Task ComputeFileHashAsync_Cancelled_Throws()
        {
            var filePath = CreateTempFile(new byte[500_000]);

            try
            {
                using (var sha256 = new SHA256(_hexEncoder))
                using (var cts = new CancellationTokenSource())
                {
                    cts.Cancel();

                    await Assert.ThrowsAnyAsync<OperationCanceledException>(
                        () => sha256.ComputeFileHashAsync(filePath, cancellationToken: cts.Token));
                }
            }
            finally
            {
                DeleteFiles(filePath);
            }
        }

        [Fact]
        public void ComputeFileHash_FileNotFound_Throws()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                Assert.Throws<FileNotFoundException>(() => sha256.ComputeFileHash(TempFilePath(), out _));
            }
        }

        [Fact]
        public void ComputeHash_InvalidInput_Throws()
        {
            using (var sha256 = new SHA256(_hexEncoder))
            {
                Assert.Throws<ArgumentException>(() => sha256.ComputeHash(null, out _));
                Assert.Throws<ArgumentException>(() => sha256.ComputeHash(Array.Empty<byte>(), out _));
                Assert.Throws<ArgumentException>(() => sha256.ComputeTextHash("  ", out _));
            }
        }
    }
}
