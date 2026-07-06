using AleCGN.Security.Cryptography.Hash;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Hmac
{
    public interface IHmac : IDisposable
    {
        void SetOrUpdateKey(byte[] key);

        void SetOrUpdateKey(string encodedKey);

        string ComputeHmac(byte[] data, out byte[] hmacBytes, int offset = 0, int count = 0);

        string ComputeTextHmac(string text, out byte[] hmacBytes, int offset = 0, int count = 0);

        string ComputeFileHmac(string filePath, out byte[] hmacBytes, int bufferSizeInKB = 64, long offset = 0L, long count = 0L);

        Task<FileHashResult> ComputeFileHmacAsync(
            string filePath,
            int bufferSizeInKB = 64,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);

        bool VerifyHmac(byte[] data, byte[] hmac, int offset = 0, int count = 0);

        bool VerifyTextHmac(string text, string encodedHmac, int offset = 0, int count = 0);

        bool VerifyFileHmac(string filePath, byte[] hmac, long offset = 0L, long count = 0L);

        bool VerifyFileHmac(string filePath, string encodedHmac, long offset = 0L, long count = 0L);
    }
}
