using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Hash
{
    public abstract class HashBase : IHash
    {
        public event EventHandler<int> OnComputeFileHashProgressChanged;

        private readonly IEncoder _encoder;
        private readonly HashAlgorithmKind _hashAlgorithmKind;

        protected HashBase(IEncoder encoder, HashAlgorithmKind hashAlgorithmKind)
        {
            _encoder = encoder;
            _hashAlgorithmKind = hashAlgorithmKind;
        }

        /// <summary>
        /// Computes hash for input data, and returns an encoded hash string.
        /// </summary>
        /// <param name="data">The source data to be computed the hash.</param>
        /// <param name="hashBytes">The computed hash as out raw bytes.</param>
        /// <param name="offset">The offset to start taking data to be computed the hash.</param>
        /// <param name="count">The ammount of data to be computed the hash (0 = all remaining data after offset).</param>
        /// <returns></returns>
        public string ComputeHash(byte[] data, out byte[] hashBytes, int offset = 0, int count = 0)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            using (var hashAlgorithm = CreateHashAlgorithm())
            {
                hashBytes = hashAlgorithm.ComputeHash(buffer: data, offset: offset, count: (count == 0 ? data.Length - offset : count));
            }

            return _encoder.Encode(hashBytes);
        }

        public string ComputeTextHash(string text, out byte[] hashBytes, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            var textSubstring = text.Substring(startIndex: offset, length: (count == 0 ? text.Length - offset : count));
            var textSubstringBytes = textSubstring.ToUTF8Bytes();

            return ComputeHash(textSubstringBytes, out hashBytes);
        }

        public string ComputeFileHash(string filePath, out byte[] hashBytes, int bufferSizeInKB = 64, long offset = 0L, long count = 0L)
        {
            CheckFileExists(filePath);

            using (var hashAlgorithm = CreateHashAlgorithm())
            {
                hashBytes = FileHashingHelper.ComputeHash(
                    hashAlgorithm,
                    filePath,
                    bufferSizeInKB,
                    offset,
                    count,
                    percentageDone => OnComputeFileHashProgressChanged?.Invoke(this, percentageDone)
                );
            }

            return _encoder.Encode(hashBytes);
        }

        public async Task<FileHashResult> ComputeFileHashAsync(
            string filePath,
            int bufferSizeInKB = 64,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
        {
            CheckFileExists(filePath);

            byte[] hashBytes;

            using (var hashAlgorithm = CreateHashAlgorithm())
            {
                hashBytes = await FileHashingHelper.ComputeHashAsync(
                    hashAlgorithm,
                    filePath,
                    bufferSizeInKB,
                    offset,
                    count,
                    progress,
                    cancellationToken
                ).ConfigureAwait(false);
            }

            return new FileHashResult(_encoder.Encode(hashBytes), hashBytes);
        }

        public Task<HashResult> ComputeHashAsync(byte[] data, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() =>
            {
                var encodedHash = ComputeHash(data, out var hashBytes, offset, count);

                return new HashResult(encodedHash, hashBytes);
            }, cancellationToken);

        public Task<HashResult> ComputeTextHashAsync(string text, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() =>
            {
                var encodedHash = ComputeTextHash(text, out var hashBytes, offset, count);

                return new HashResult(encodedHash, hashBytes);
            }, cancellationToken);

        public bool VerifyHash(byte[] data, byte[] hash, int offset = 0, int count = 0)
        {
            if (hash is null || hash.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hash));
            }

            ComputeHash(data, out var computedHashBytes, offset, count);

            return CryptographyHelper.FixedTimeEquals(computedHashBytes, hash);
        }

        public bool VerifyTextHash(string text, string hash, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hash));
            }

            ComputeTextHash(text, out var computedHashBytes, offset, count);

            return CryptographyHelper.FixedTimeEquals(computedHashBytes, _encoder.Decode(hash));
        }

        public bool VerifyFileHash(string filePath, byte[] hash, long offset = 0L, long count = 0L)
        {
            if (hash is null || hash.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hash));
            }

            ComputeFileHash(filePath, out var computedHashBytes, offset: offset, count: count);

            return CryptographyHelper.FixedTimeEquals(computedHashBytes, hash);
        }

        public bool VerifyFileHash(string filePath, string hash, long offset = 0L, long count = 0L)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hash));
            }

            ComputeFileHash(filePath, out var computedHashBytes, offset: offset, count: count);

            return CryptographyHelper.FixedTimeEquals(computedHashBytes, _encoder.Decode(hash));
        }

        public Task<bool> VerifyHashAsync(byte[] data, byte[] hash, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyHash(data, hash, offset, count), cancellationToken);

        public Task<bool> VerifyTextHashAsync(string text, string hash, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyTextHash(text, hash, offset, count), cancellationToken);

        public async Task<bool> VerifyFileHashAsync(
            string filePath,
            byte[] hash,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
        {
            if (hash is null || hash.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hash));
            }

            var result = await ComputeFileHashAsync(filePath, offset: offset, count: count, progress: progress, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            return CryptographyHelper.FixedTimeEquals(result.HashBytes, hash);
        }

        public async Task<bool> VerifyFileHashAsync(
            string filePath,
            string hash,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hash));
            }

            var result = await ComputeFileHashAsync(filePath, offset: offset, count: count, progress: progress, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            return CryptographyHelper.FixedTimeEquals(result.HashBytes, _encoder.Decode(hash));
        }

        public void Dispose()
        {
            // Kept for backwards compatibility: hash algorithm instances are created
            // and disposed per operation, so there is no shared state to release.
        }

        private static void CheckFileExists(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(LibraryResources.Validation_FileNotFound, filePath);
            }
        }

        private HashAlgorithm CreateHashAlgorithm()
        {
            switch (_hashAlgorithmKind)
            {
                case HashAlgorithmKind.MD5:
                    return System.Security.Cryptography.MD5.Create();
                case HashAlgorithmKind.SHA1:
                    return System.Security.Cryptography.SHA1.Create();
                case HashAlgorithmKind.SHA256:
                    return System.Security.Cryptography.SHA256.Create();
                case HashAlgorithmKind.SHA384:
                    return System.Security.Cryptography.SHA384.Create();
                case HashAlgorithmKind.SHA512:
                    return System.Security.Cryptography.SHA512.Create();
                default:
                    throw new CryptographicException($"Unsupported hash algorithm: {_hashAlgorithmKind}.");
            }
        }
    }
}
