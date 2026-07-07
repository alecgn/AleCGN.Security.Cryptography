using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Hash;
using AleCGN.Security.Cryptography.Helpers;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Hmac
{
    public abstract class HmacBase : IHmac
    {
        public event EventHandler<int> OnComputeFileHmacProgressChanged;

        private readonly IEncoder _encoder;
        private readonly HashAlgorithmKind _hashAlgorithmKind;
        private byte[] _key;
        private bool _disposed;

        protected HmacBase(IEncoder encoder, HashAlgorithmKind hashAlgorithmKind)
        {
            _encoder = encoder;
            _hashAlgorithmKind = hashAlgorithmKind;
        }

        protected HmacBase(IEncoder encoder, HashAlgorithmKind hashAlgorithmKind, byte[] key)
            : this(encoder, hashAlgorithmKind)
        {
            SetOrUpdateKey(key);
        }

        protected HmacBase(IEncoder encoder, HashAlgorithmKind hashAlgorithmKind, string encodedKey)
            : this(encoder, hashAlgorithmKind)
        {
            SetOrUpdateKey(encodedKey);
        }

        public void SetOrUpdateKey(byte[] key)
        {
            if (key is null || key.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(key));
            }

            // Defensive copy: mutations to the caller's array must not affect the key in use.
            var newKey = (byte[])key.Clone();

            ClearKey();

            _key = newKey;
        }

        public void SetOrUpdateKey(string encodedKey)
        {
            if (string.IsNullOrWhiteSpace(encodedKey))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encodedKey));
            }

            var newKey = _encoder.Decode(encodedKey);

            ClearKey();

            _key = newKey;
        }

        public string ComputeHmac(byte[] data, out byte[] hmacBytes, int offset = 0, int count = 0)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            CheckKeySet();

            using (var hmacAlgorithm = CreateHmacAlgorithm())
            {
                hmacBytes = hmacAlgorithm.ComputeHash(buffer: data, offset: offset, count: (count == 0 ? data.Length - offset : count));
            }

            return _encoder.Encode(hmacBytes);
        }

        public string ComputeTextHmac(string text, out byte[] hmacBytes, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            var textSubstring = text.Substring(startIndex: offset, length: (count == 0 ? text.Length - offset : count));
            var textSubstringBytes = textSubstring.ToUTF8Bytes();

            return ComputeHmac(textSubstringBytes, out hmacBytes);
        }

        public string ComputeFileHmac(string filePath, out byte[] hmacBytes, int bufferSizeInKB = 64, long offset = 0L, long count = 0L)
        {
            CheckFileExists(filePath);
            CheckKeySet();

            using (var hmacAlgorithm = CreateHmacAlgorithm())
            {
                hmacBytes = FileHashingHelper.ComputeHash(
                    hmacAlgorithm,
                    filePath,
                    bufferSizeInKB,
                    offset,
                    count,
                    percentageDone => OnComputeFileHmacProgressChanged?.Invoke(this, percentageDone)
                );
            }

            return _encoder.Encode(hmacBytes);
        }

        public async Task<FileHashResult> ComputeFileHmacAsync(
            string filePath,
            int bufferSizeInKB = 64,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
        {
            CheckFileExists(filePath);
            CheckKeySet();

            byte[] hmacBytes;

            using (var hmacAlgorithm = CreateHmacAlgorithm())
            {
                hmacBytes = await FileHashingHelper.ComputeHashAsync(
                    hmacAlgorithm,
                    filePath,
                    bufferSizeInKB,
                    offset,
                    count,
                    progress,
                    cancellationToken
                ).ConfigureAwait(false);
            }

            return new FileHashResult(_encoder.Encode(hmacBytes), hmacBytes);
        }

        public Task<HashResult> ComputeHmacAsync(byte[] data, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() =>
            {
                var encodedHmac = ComputeHmac(data, out var hmacBytes, offset, count);

                return new HashResult(encodedHmac, hmacBytes);
            }, cancellationToken);

        public Task<HashResult> ComputeTextHmacAsync(string text, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() =>
            {
                var encodedHmac = ComputeTextHmac(text, out var hmacBytes, offset, count);

                return new HashResult(encodedHmac, hmacBytes);
            }, cancellationToken);

        public bool VerifyHmac(byte[] data, byte[] hmac, int offset = 0, int count = 0)
        {
            if (hmac is null || hmac.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hmac));
            }

            ComputeHmac(data, out var computedHmacBytes, offset, count);

            return CryptographyHelper.FixedTimeEquals(computedHmacBytes, hmac);
        }

        public bool VerifyTextHmac(string text, string encodedHmac, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(encodedHmac))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encodedHmac));
            }

            ComputeTextHmac(text, out var computedHmacBytes, offset, count);

            return CryptographyHelper.FixedTimeEquals(computedHmacBytes, _encoder.Decode(encodedHmac));
        }

        public bool VerifyFileHmac(string filePath, byte[] hmac, long offset = 0L, long count = 0L)
        {
            if (hmac is null || hmac.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hmac));
            }

            ComputeFileHmac(filePath, out var computedHmacBytes, offset: offset, count: count);

            return CryptographyHelper.FixedTimeEquals(computedHmacBytes, hmac);
        }

        public bool VerifyFileHmac(string filePath, string encodedHmac, long offset = 0L, long count = 0L)
        {
            if (string.IsNullOrWhiteSpace(encodedHmac))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encodedHmac));
            }

            ComputeFileHmac(filePath, out var computedHmacBytes, offset: offset, count: count);

            return CryptographyHelper.FixedTimeEquals(computedHmacBytes, _encoder.Decode(encodedHmac));
        }

        public Task<bool> VerifyHmacAsync(byte[] data, byte[] hmac, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyHmac(data, hmac, offset, count), cancellationToken);

        public Task<bool> VerifyTextHmacAsync(string text, string encodedHmac, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
            => Task.Run(() => VerifyTextHmac(text, encodedHmac, offset, count), cancellationToken);

        public async Task<bool> VerifyFileHmacAsync(
            string filePath,
            byte[] hmac,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
        {
            if (hmac is null || hmac.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hmac));
            }

            var result = await ComputeFileHmacAsync(filePath, offset: offset, count: count, progress: progress, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            return CryptographyHelper.FixedTimeEquals(result.HashBytes, hmac);
        }

        public async Task<bool> VerifyFileHmacAsync(
            string filePath,
            string encodedHmac,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(encodedHmac))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(encodedHmac));
            }

            var result = await ComputeFileHmacAsync(filePath, offset: offset, count: count, progress: progress, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            return CryptographyHelper.FixedTimeEquals(result.HashBytes, _encoder.Decode(encodedHmac));
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            ClearKey();

            _disposed = true;
        }

        private static void CheckFileExists(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(LibraryResources.Validation_FileNotFound, filePath);
            }
        }

        private void CheckKeySet()
        {
            if (_key == null || _key.Length == 0)
            {
                throw new CryptographicException(LibraryResources.Validation_KeyNotSet);
            }
        }

        private void ClearKey()
        {
            if (_key != null)
            {
                Array.Clear(_key, 0, _key.Length);

                _key = null;
            }
        }

        private HMAC CreateHmacAlgorithm()
        {
            switch (_hashAlgorithmKind)
            {
                case HashAlgorithmKind.MD5:
                    return new System.Security.Cryptography.HMACMD5(_key);
                case HashAlgorithmKind.SHA1:
                    return new System.Security.Cryptography.HMACSHA1(_key);
                case HashAlgorithmKind.SHA256:
                    return new System.Security.Cryptography.HMACSHA256(_key);
                case HashAlgorithmKind.SHA384:
                    return new System.Security.Cryptography.HMACSHA384(_key);
                case HashAlgorithmKind.SHA512:
                    return new System.Security.Cryptography.HMACSHA512(_key);
                default:
                    throw new CryptographicException($"Unsupported hash algorithm: {_hashAlgorithmKind}.");
            }
        }
    }
}
