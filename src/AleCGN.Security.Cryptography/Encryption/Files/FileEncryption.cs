using AleCGN.Security.Cryptography.Constants;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Encryption.Files
{
    /// <summary>
    /// Streaming file encryption on top of AES-GCM: the file is processed in chunks, so files of any
    /// size are encrypted with constant memory usage. Each chunk is individually authenticated, and its
    /// index and a final-chunk flag are bound as associated data, so reordering, truncating or removing
    /// chunks makes decryption fail.
    /// File layout: magic (4) | version (1) | file id (8) | chunk size (4, little-endian) | chunks.
    /// Each chunk: payload size (4, little-endian) | AES-GCM output (ciphertext || tag || nonce).
    /// </summary>
    public class FileEncryption : IFileEncryption
    {
        private static readonly byte[] _magicBytes = { 0x41, 0x43, 0x46, 0x45 }; // "ACFE"
        private const byte _formatVersion = 1;
        private const int _fileIdSize = 8;
        private const int _headerSize = 4 + 1 + _fileIdSize + 4;
        private const int _chunkPrefixSize = 4;
        private const int _associatedDataSize = _fileIdSize + 4 + 1;
        private const int _defaultChunkSizeInKB = 1024;
        private const byte _lastChunkFlag = 1;

        private readonly IAesGcmBase _cipher;
        private readonly int _chunkSize;

        public FileEncryption(IAesGcmBase cipher) : this(cipher, _defaultChunkSizeInKB) { }

        public FileEncryption(IAesGcmBase cipher, int chunkSizeInKB)
        {
            if (cipher is null)
            {
                throw new ArgumentNullException(nameof(cipher));
            }

            if (chunkSizeInKB <= 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentOutOfRange, nameof(chunkSizeInKB));
            }

            _cipher = cipher;
            _chunkSize = chunkSizeInKB * ConstantValues.BytesPerKilobyte;
        }

        public void EncryptFile(string inputFilePath, string outputFilePath, IProgress<int> progress = null)
            => EncryptFileInternalAsync(inputFilePath, outputFilePath, progress, CancellationToken.None, runSynchronously: true)
                .GetAwaiter().GetResult();

        public void DecryptFile(string inputFilePath, string outputFilePath, IProgress<int> progress = null)
            => DecryptFileInternalAsync(inputFilePath, outputFilePath, progress, CancellationToken.None, runSynchronously: true)
                .GetAwaiter().GetResult();

        public Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
            => EncryptFileInternalAsync(inputFilePath, outputFilePath, progress, cancellationToken, runSynchronously: false);

        public Task DecryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
            => DecryptFileInternalAsync(inputFilePath, outputFilePath, progress, cancellationToken, runSynchronously: false);

        #region Private methods

        private async Task EncryptFileInternalAsync(
            string inputFilePath,
            string outputFilePath,
            IProgress<int> progress,
            CancellationToken cancellationToken,
            bool runSynchronously)
        {
            CheckInputFile(inputFilePath);

            var fileId = CryptographyHelper.GenerateSecureRandomBytes(_fileIdSize);
            var buffer = new byte[_chunkSize];

            using (var inputStream = CreateReadStream(inputFilePath, runSynchronously))
            using (var outputStream = CreateWriteStream(outputFilePath, runSynchronously))
            {
                if (inputStream.Length == 0)
                {
                    ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(inputFilePath));
                }

                WriteHeader(outputStream, fileId);

                var total = inputStream.Length;
                var remaining = total;
                var chunkIndex = 0;
                var percentageDone = 0;

                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var bytesRead = runSynchronously
                        ? inputStream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining))
                        : await inputStream.ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, remaining), cancellationToken).ConfigureAwait(false);

                    if (bytesRead == 0)
                    {
                        break;
                    }

                    remaining -= bytesRead;

                    var chunk = new byte[bytesRead];

                    Array.Copy(buffer, 0, chunk, 0, bytesRead);

                    var associatedData = BuildChunkAssociatedData(fileId, chunkIndex, isLastChunk: remaining == 0);
                    var encryptedChunk = _cipher.EncryptData(chunk, associatedData);
                    var chunkPrefix = ToLittleEndianBytes(encryptedChunk.Length);

                    if (runSynchronously)
                    {
                        outputStream.Write(chunkPrefix, 0, chunkPrefix.Length);
                        outputStream.Write(encryptedChunk, 0, encryptedChunk.Length);
                    }
                    else
                    {
                        await outputStream.WriteAsync(chunkPrefix, 0, chunkPrefix.Length, cancellationToken).ConfigureAwait(false);
                        await outputStream.WriteAsync(encryptedChunk, 0, encryptedChunk.Length, cancellationToken).ConfigureAwait(false);
                    }

                    chunkIndex++;

                    ReportProgress(total, remaining, ref percentageDone, progress);
                }
            }
        }

        private async Task DecryptFileInternalAsync(
            string inputFilePath,
            string outputFilePath,
            IProgress<int> progress,
            CancellationToken cancellationToken,
            bool runSynchronously)
        {
            CheckInputFile(inputFilePath);

            using (var inputStream = CreateReadStream(inputFilePath, runSynchronously))
            using (var outputStream = CreateWriteStream(outputFilePath, runSynchronously))
            {
                var (fileId, originalChunkSize) = ReadAndValidateHeader(inputStream);

                var total = inputStream.Length;
                var chunkIndex = 0;
                var percentageDone = 0;
                var lastChunkProcessed = false;

                while (inputStream.Position < inputStream.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (lastChunkProcessed)
                    {
                        // Data found after the chunk flagged as last: corrupted/tampered stream.
                        throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputFilePath));
                    }

                    var encryptedChunk = ReadChunk(inputStream, originalChunkSize);
                    var isLastChunk = inputStream.Position >= inputStream.Length;
                    var associatedData = BuildChunkAssociatedData(fileId, chunkIndex, isLastChunk);

                    // Throws CryptographicException on tag mismatch (tampering, reordering or truncation).
                    var decryptedChunk = _cipher.DecryptData(encryptedChunk, associatedData);

                    if (runSynchronously)
                    {
                        outputStream.Write(decryptedChunk, 0, decryptedChunk.Length);
                    }
                    else
                    {
                        await outputStream.WriteAsync(decryptedChunk, 0, decryptedChunk.Length, cancellationToken).ConfigureAwait(false);
                    }

                    chunkIndex++;
                    lastChunkProcessed = isLastChunk;

                    ReportProgress(total, total - inputStream.Position, ref percentageDone, progress);
                }

                if (!lastChunkProcessed)
                {
                    throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputFilePath));
                }
            }
        }

        private static void CheckInputFile(string inputFilePath)
        {
            if (!File.Exists(inputFilePath))
            {
                throw new FileNotFoundException(LibraryResources.Validation_FileNotFound, inputFilePath);
            }
        }

        private FileStream CreateReadStream(string filePath, bool runSynchronously)
            => new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.Read, _chunkSize,
                runSynchronously ? FileOptions.SequentialScan : FileOptions.SequentialScan | FileOptions.Asynchronous);

        private FileStream CreateWriteStream(string filePath, bool runSynchronously)
            => new FileStream(
                filePath, FileMode.Create, FileAccess.Write, FileShare.None, _chunkSize,
                runSynchronously ? FileOptions.None : FileOptions.Asynchronous);

        private void WriteHeader(Stream outputStream, byte[] fileId)
        {
            outputStream.Write(_magicBytes, 0, _magicBytes.Length);
            outputStream.WriteByte(_formatVersion);
            outputStream.Write(fileId, 0, fileId.Length);

            var chunkSizeBytes = ToLittleEndianBytes(_chunkSize);

            outputStream.Write(chunkSizeBytes, 0, chunkSizeBytes.Length);
        }

        private static (byte[] FileId, int OriginalChunkSize) ReadAndValidateHeader(Stream inputStream)
        {
            var header = new byte[_headerSize];

            if (inputStream.Length <= _headerSize || ReadExactly(inputStream, header, _headerSize) != _headerSize)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
            }

            for (var index = 0; index < _magicBytes.Length; index++)
            {
                if (header[index] != _magicBytes[index])
                {
                    throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
                }
            }

            if (header[_magicBytes.Length] != _formatVersion)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
            }

            var fileId = new byte[_fileIdSize];

            Array.Copy(header, _magicBytes.Length + 1, fileId, 0, _fileIdSize);

            var originalChunkSize = FromLittleEndianBytes(new[]
            {
                header[_magicBytes.Length + 1 + _fileIdSize],
                header[_magicBytes.Length + 1 + _fileIdSize + 1],
                header[_magicBytes.Length + 1 + _fileIdSize + 2],
                header[_magicBytes.Length + 1 + _fileIdSize + 3]
            });

            if (originalChunkSize <= 0)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
            }

            return (fileId, originalChunkSize);
        }

        private static byte[] ReadChunk(Stream inputStream, int originalChunkSize)
        {
            var chunkPrefix = new byte[_chunkPrefixSize];

            if (ReadExactly(inputStream, chunkPrefix, _chunkPrefixSize) != _chunkPrefixSize)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
            }

            var chunkLength = FromLittleEndianBytes(chunkPrefix);

            // An encrypted chunk is never larger than the original chunk size + AES-GCM metadata (tag 16 + nonce 12).
            if (chunkLength <= 0 || chunkLength > originalChunkSize + 28 || inputStream.Position + chunkLength > inputStream.Length)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
            }

            var encryptedChunk = new byte[chunkLength];

            if (ReadExactly(inputStream, encryptedChunk, chunkLength) != chunkLength)
            {
                throw new ArgumentException(LibraryResources.Validation_InvalidPayloadFormat, nameof(inputStream));
            }

            return encryptedChunk;
        }

        private static int ReadExactly(Stream stream, byte[] buffer, int count)
        {
            var totalBytesRead = 0;

            while (totalBytesRead < count)
            {
                var bytesRead = stream.Read(buffer, totalBytesRead, count - totalBytesRead);

                if (bytesRead == 0)
                {
                    break;
                }

                totalBytesRead += bytesRead;
            }

            return totalBytesRead;
        }

        private static byte[] BuildChunkAssociatedData(byte[] fileId, int chunkIndex, bool isLastChunk)
        {
            var associatedData = new byte[_associatedDataSize];

            Array.Copy(fileId, 0, associatedData, 0, _fileIdSize);

            associatedData[_fileIdSize] = (byte)(chunkIndex & 0xFF);
            associatedData[_fileIdSize + 1] = (byte)((chunkIndex >> 8) & 0xFF);
            associatedData[_fileIdSize + 2] = (byte)((chunkIndex >> 16) & 0xFF);
            associatedData[_fileIdSize + 3] = (byte)((chunkIndex >> 24) & 0xFF);
            associatedData[_fileIdSize + 4] = isLastChunk ? _lastChunkFlag : (byte)0;

            return associatedData;
        }

        private static byte[] ToLittleEndianBytes(int value)
            => new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF)
            };

        private static int FromLittleEndianBytes(byte[] bytes)
            => bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);

        private static void ReportProgress(long total, long remaining, ref int percentageDone, IProgress<int> progress)
        {
            if (progress is null)
            {
                return;
            }

            var tmpPercentageDone = (int)((total - remaining) * 100 / total);

            if (tmpPercentageDone != percentageDone)
            {
                percentageDone = tmpPercentageDone;

                progress.Report(percentageDone);
            }
        }

        #endregion Private methods
    }
}
