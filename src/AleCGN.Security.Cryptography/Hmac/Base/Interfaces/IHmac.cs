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

        Task<HashResult> ComputeHmacAsync(byte[] data, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<HashResult> ComputeTextHmacAsync(string text, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

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

        Task<bool> VerifyHmacAsync(byte[] data, byte[] hmac, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<bool> VerifyTextHmacAsync(string text, string encodedHmac, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<bool> VerifyFileHmacAsync(
            string filePath,
            byte[] hmac,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);

        Task<bool> VerifyFileHmacAsync(
            string filePath,
            string encodedHmac,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);
    }
}
