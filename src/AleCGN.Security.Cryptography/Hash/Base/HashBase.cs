using AleCGN.Security.Cryptography.Constants;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System;
using System.IO;
using System.Security.Authentication;
using System.Security.Cryptography;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Hash
{
    public abstract class HashBase : IHash
    {
        public event EventHandler<int> OnComputeFileHashProgressChanged;

        private readonly IEncoder _encoder;
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly HashAlgorithmType _hashAlgorithmType;

        public HashBase(IEncoder encoder, HashAlgorithmType hashAlgorithmType)
        {
            _encoder = encoder;
            _hashAlgorithmType = hashAlgorithmType;
            _hashAlgorithm = HashAlgorithm.Create(_hashAlgorithmType.ToString());
        }

        /// <summary>
        /// Computes hash for input data, and returns an encoded hash string.
        /// </summary>
        /// <param name="data">The source data to be computed the hash.</param>
        /// <param name="hashBytes">The computed hash as out raw bytes.</param>
        /// <param name="offset">The offset to start taking data to be computed the hash.</param>
        /// <param name="count">The ammount of data to be computed the hash.</param>
        /// <returns></returns>
        public string ComputeHash(byte[] data, out byte[] hashBytes, int offset = 0, int count = 0)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            hashBytes = _hashAlgorithm.ComputeHash(buffer: data, offset: offset, count: (count == 0 ? data.Length : count));

            return _encoder.Encode(hashBytes);
        }

        public string ComputeTextHash(string text, out byte[] hashBytes, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            var textSubstring = text.Substring(startIndex: offset, length: (count == 0 ? text.Length : count));
            var textSubstringBytes = textSubstring.ToUTF8Bytes();
            var hash = ComputeHash(textSubstringBytes, out hashBytes);
            
            return hash;
        }

        public string ComputeFileHash(string filePath, out byte[] hashBytes, int bufferSizeInKB = 4, long offset = 0L, long count = 0L)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(LibraryResources.Validation_FileNotFound, filePath);
            }

            using (var fStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                count = (count == 0 ? fStream.Length : count);
                fStream.Seek(offset, SeekOrigin.Begin);
                //var buffer = new byte[10];
                var buffer = new byte[bufferSizeInKB * ConstantValues.BytesPerKilobyte];
                var amount = (count - offset);

                var percentageDone = 0;

                while (amount > 0)
                {
                    var bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                    amount -= bytesRead;

                    if (amount > 0)
                    {
                        _hashAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                    }
                    else
                    {
                        _hashAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                    }

                    var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                    if (tmpPercentageDone != percentageDone)
                    {
                        percentageDone = tmpPercentageDone;

                        OnComputeFileHashProgressChanged?.Invoke(this, percentageDone);
                    }
                }
            }

            hashBytes = _hashAlgorithm.Hash;

            return _encoder.Encode(_hashAlgorithm.Hash);
        }

        public string VerifyHash(byte[] data, byte[] hash, int offset = 0, int count = 0)
        {
            throw new System.NotImplementedException();
        }

        public string VerifyTextHash(string text, string hash, int offset = 0, int count = 0)
        {
            throw new System.NotImplementedException();
        }

        public string VerifyFileHash(string filePath, byte[] hash, long offset = 0, long count = 0)
        {
            throw new System.NotImplementedException();
        }

        public string VerifyFileHash(string filePath, string hash, long offset = 0, long count = 0)
        {
            throw new System.NotImplementedException();
        }

        public void Dispose() =>
            _hashAlgorithm?.Dispose();
    }
}
