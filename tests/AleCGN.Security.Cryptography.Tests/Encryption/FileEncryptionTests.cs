using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Encryption.Files;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using static AleCGN.Security.Cryptography.Tests.TestUtils;

namespace AleCGN.Security.Cryptography.Tests.Encryption
{
    public class FileEncryptionTests : IDisposable
    {
        private static readonly Base64Encoder _encoder = new Base64Encoder();
        private readonly AesGcm256 _aes;
        private readonly FileEncryption _fileEncryption;

        public FileEncryptionTests()
        {
            _aes = new AesGcm256(_encoder, new SymmetricKeyHelper(_encoder).GenerateSecureRandom256BitKey());
            _fileEncryption = new FileEncryption(_aes, chunkSizeInKB: 4);
        }

        public void Dispose() => _aes.Dispose();

        private static byte[] RandomContent(int size)
        {
            var content = new byte[size];

            new Random(size).NextBytes(content);

            return content;
        }

        // Sizes around the 4 KB chunk boundary: single partial chunk, exact multiple, multiple chunks
        [Theory]
        [InlineData(1)]
        [InlineData(4096)]
        [InlineData(4097)]
        [InlineData(8192)]
        [InlineData(10_000)]
        public void EncryptDecrypt_Roundtrip_AroundChunkBoundaries(int size)
        {
            var content = RandomContent(size);
            var plainPath = CreateTempFile(content);
            var encryptedPath = TempFilePath();
            var decryptedPath = TempFilePath();

            try
            {
                _fileEncryption.EncryptFile(plainPath, encryptedPath);
                _fileEncryption.DecryptFile(encryptedPath, decryptedPath);

                Assert.Equal(content, File.ReadAllBytes(decryptedPath));
            }
            finally
            {
                DeleteFiles(plainPath, encryptedPath, decryptedPath);
            }
        }

        [Fact]
        public async Task EncryptDecrypt_Async_Roundtrip_WithProgress()
        {
            var content = RandomContent(20_000);
            var plainPath = CreateTempFile(content);
            var encryptedPath = TempFilePath();
            var decryptedPath = TempFilePath();

            try
            {
                await _fileEncryption.EncryptFileAsync(plainPath, encryptedPath, new Progress<int>());
                await _fileEncryption.DecryptFileAsync(encryptedPath, decryptedPath, new Progress<int>());

                Assert.Equal(content, File.ReadAllBytes(decryptedPath));
            }
            finally
            {
                DeleteFiles(plainPath, encryptedPath, decryptedPath);
            }
        }

        [Fact]
        public void Decrypt_WithDifferentChunkSizeInstance_Works()
        {
            var content = RandomContent(10_000);
            var plainPath = CreateTempFile(content);
            var encryptedPath = TempFilePath();
            var decryptedPath = TempFilePath();

            try
            {
                _fileEncryption.EncryptFile(plainPath, encryptedPath); // 4 KB chunks

                var otherInstance = new FileEncryption(_aes, chunkSizeInKB: 64);

                otherInstance.DecryptFile(encryptedPath, decryptedPath); // chunk size read from header

                Assert.Equal(content, File.ReadAllBytes(decryptedPath));
            }
            finally
            {
                DeleteFiles(plainPath, encryptedPath, decryptedPath);
            }
        }

        [Fact]
        public void Decrypt_TruncatedFile_Fails()
        {
            var plainPath = CreateTempFile(RandomContent(10_000));
            var encryptedPath = TempFilePath();
            var decryptedPath = TempFilePath();

            try
            {
                _fileEncryption.EncryptFile(plainPath, encryptedPath);

                var encryptedBytes = File.ReadAllBytes(encryptedPath);

                // Remove the trailing bytes (part of the last chunk)
                File.WriteAllBytes(encryptedPath, encryptedBytes.Take(encryptedBytes.Length - 200).ToArray());

                Assert.ThrowsAny<Exception>(() => _fileEncryption.DecryptFile(encryptedPath, decryptedPath));
            }
            finally
            {
                DeleteFiles(plainPath, encryptedPath, decryptedPath);
            }
        }

        [Fact]
        public void Decrypt_TamperedChunk_Fails()
        {
            var plainPath = CreateTempFile(RandomContent(10_000));
            var encryptedPath = TempFilePath();
            var decryptedPath = TempFilePath();

            try
            {
                _fileEncryption.EncryptFile(plainPath, encryptedPath);

                var encryptedBytes = File.ReadAllBytes(encryptedPath);

                encryptedBytes[100] ^= 0xFF; // inside the first chunk's ciphertext

                File.WriteAllBytes(encryptedPath, encryptedBytes);

                Assert.ThrowsAny<Exception>(() => _fileEncryption.DecryptFile(encryptedPath, decryptedPath));
            }
            finally
            {
                DeleteFiles(plainPath, encryptedPath, decryptedPath);
            }
        }

        [Fact]
        public void Decrypt_NotAnEncryptedFile_Throws()
        {
            var plainPath = CreateTempFile(RandomContent(1_000));
            var decryptedPath = TempFilePath();

            try
            {
                Assert.Throws<ArgumentException>(() => _fileEncryption.DecryptFile(plainPath, decryptedPath));
            }
            finally
            {
                DeleteFiles(plainPath, decryptedPath);
            }
        }

        [Fact]
        public void Encrypt_EmptyFile_Throws()
        {
            var emptyPath = CreateTempFile(string.Empty);
            var encryptedPath = TempFilePath();

            try
            {
                Assert.Throws<ArgumentException>(() => _fileEncryption.EncryptFile(emptyPath, encryptedPath));
            }
            finally
            {
                DeleteFiles(emptyPath, encryptedPath);
            }
        }

        [Fact]
        public async Task Encrypt_Cancelled_Throws()
        {
            var plainPath = CreateTempFile(RandomContent(100_000));
            var encryptedPath = TempFilePath();

            try
            {
                using (var cts = new CancellationTokenSource())
                {
                    cts.Cancel();

                    await Assert.ThrowsAnyAsync<OperationCanceledException>(
                        () => _fileEncryption.EncryptFileAsync(plainPath, encryptedPath, cancellationToken: cts.Token));
                }
            }
            finally
            {
                DeleteFiles(plainPath, encryptedPath);
            }
        }

        [Fact]
        public void Encrypt_InputFileNotFound_Throws()
            => Assert.Throws<FileNotFoundException>(() => _fileEncryption.EncryptFile(TempFilePath(), TempFilePath()));

        [Fact]
        public void Constructor_InvalidArguments_Throw()
        {
            Assert.Throws<ArgumentNullException>(() => new FileEncryption(null));
            Assert.Throws<ArgumentException>(() => new FileEncryption(_aes, chunkSizeInKB: 0));
        }
    }
}
