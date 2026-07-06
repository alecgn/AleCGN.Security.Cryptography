using AleCGN.Security.Cryptography.Constants;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.IO;
using System.Security.Cryptography;
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
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(LibraryResources.Validation_FileNotFound, filePath);
            }

            var buffer = new byte[bufferSizeInKB * ConstantValues.BytesPerKilobyte];

            using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, buffer.Length, FileOptions.SequentialScan))
            using (var hashAlgorithm = CreateHashAlgorithm())
            {
                fileStream.Seek(offset, SeekOrigin.Begin);

                var total = (count == 0 ? fileStream.Length - offset : count);
                var remaining = total;
                var percentageDone = 0;

                while (remaining > 0)
                {
                    var bytesRead = fileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));

                    if (bytesRead == 0)
                    {
                        break;
                    }

                    remaining -= bytesRead;

                    if (remaining > 0)
                    {
                        hashAlgorithm.TransformBlock(buffer, 0, bytesRead, null, 0);
                    }
                    else
                    {
                        hashAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                    }

                    var tmpPercentageDone = (int)((total - remaining) * 100 / total);

                    if (tmpPercentageDone != percentageDone)
                    {
                        percentageDone = tmpPercentageDone;

                        OnComputeFileHashProgressChanged?.Invoke(this, percentageDone);
                    }
                }

                if (remaining > 0 || total == 0)
                {
                    hashAlgorithm.TransformFinalBlock(buffer, 0, 0);
                }

                hashBytes = hashAlgorithm.Hash;
            }

            return _encoder.Encode(hashBytes);
        }

        public bool VerifyHash(byte[] data, byte[] hash, int offset = 0, int count = 0)
        {
            if (hash is null || hash.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hash));
            }

            ComputeHash(data, out var computedHashBytes, offset, count);

            return FixedTimeEquals(computedHashBytes, hash);
        }

        public bool VerifyTextHash(string text, string hash, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hash));
            }

            ComputeTextHash(text, out var computedHashBytes, offset, count);

            return FixedTimeEquals(computedHashBytes, _encoder.Decode(hash));
        }

        public bool VerifyFileHash(string filePath, byte[] hash, long offset = 0L, long count = 0L)
        {
            if (hash is null || hash.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(hash));
            }

            ComputeFileHash(filePath, out var computedHashBytes, offset: offset, count: count);

            return FixedTimeEquals(computedHashBytes, hash);
        }

        public bool VerifyFileHash(string filePath, string hash, long offset = 0L, long count = 0L)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(hash));
            }

            ComputeFileHash(filePath, out var computedHashBytes, offset: offset, count: count);

            return FixedTimeEquals(computedHashBytes, _encoder.Decode(hash));
        }

        public void Dispose()
        {
            // Kept for backwards compatibility: hash algorithm instances are created
            // and disposed per operation, so there is no shared state to release.
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

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
#if NETSTANDARD2_0
            if (left is null || right is null || left.Length != right.Length)
            {
                return false;
            }

            var difference = 0;

            for (var i = 0; i < left.Length; i++)
            {
                difference |= left[i] ^ right[i];
            }

            return difference == 0;
#else
            return left != null && right != null && CryptographicOperations.FixedTimeEquals(left, right);
#endif
        }
    }
}
