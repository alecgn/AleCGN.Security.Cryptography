using System;
using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Hash
{
    public interface IHash : IDisposable
    {
        string ComputeHash(byte[] data, out byte[] hashBytes, int offset = 0, int count = 0);

        string ComputeTextHash(string text, out byte[] hashBytes, int offset = 0, int count = 0);

        string ComputeFileHash(string filePath, out byte[] hashBytes, int bufferSizeInKB = 64, long offset = 0L, long count = 0L);

        Task<HashResult> ComputeHashAsync(byte[] data, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<HashResult> ComputeTextHashAsync(string text, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<FileHashResult> ComputeFileHashAsync(
            string filePath,
            int bufferSizeInKB = 64,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);

        bool VerifyHash(byte[] data, byte[] hash, int offset = 0, int count = 0);

        bool VerifyTextHash(string text, string hash, int offset = 0, int count = 0);

        bool VerifyFileHash(string filePath, byte[] hash, long offset = 0L, long count = 0L);

        bool VerifyFileHash(string filePath, string hash, long offset = 0L, long count = 0L);

        Task<bool> VerifyHashAsync(byte[] data, byte[] hash, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<bool> VerifyTextHashAsync(string text, string hash, int offset = 0, int count = 0, CancellationToken cancellationToken = default);

        Task<bool> VerifyFileHashAsync(
            string filePath,
            byte[] hash,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);

        Task<bool> VerifyFileHashAsync(
            string filePath,
            string hash,
            long offset = 0L,
            long count = 0L,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);
    }
}
