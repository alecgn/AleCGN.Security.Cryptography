using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encoders.Extensions;
using AleCGN.Security.Cryptography.Resources;
using System.Security.Authentication;
using System.Security.Cryptography;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Hash
{
    public abstract class HashBase : IHash
    {
        private readonly IEncoder _encoder;
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly HashAlgorithmType _hashAlgorithmType;

        public HashBase(IEncoder encoder, HashAlgorithmType hashAlgorithmType)
        {
            _encoder = encoder;
            _hashAlgorithmType = hashAlgorithmType;
            _hashAlgorithm = HashAlgorithm.Create(_hashAlgorithmType.ToString());
        }

        public string ComputeHash(byte[] data, int offset = 0, int count = 0)
        {
            if (data is null || data.Length == 0)
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentDataNullOrZeroLength, nameof(data));
            }

            var hash = _hashAlgorithm.ComputeHash(data, offset, (count == 0 ? data.Length : count));

            return _encoder.Encode(hash);
        }

        public string ComputeTextHash(string text, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ThrowFormattedArgumentException(LibraryResources.Validation_ArgumentStringNullEmpytOrWhitespace, nameof(text));
            }

            var textSubstring = text.Substring(offset, (count == 0 ? text.Length : count));
            var textSubstringBytes = textSubstring.ToUTF8Bytes();
            var hash = ComputeHash(textSubstringBytes);
            
            return hash;
        }

        public string ComputeFileHash(string filePath, long offset = 0, long count = 0)
        {
            throw new System.NotImplementedException();
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
