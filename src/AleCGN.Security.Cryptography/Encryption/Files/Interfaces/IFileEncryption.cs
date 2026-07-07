using System;
using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Encryption.Files
{
    public interface IFileEncryption
    {
        void EncryptFile(string inputFilePath, string outputFilePath, IProgress<int> progress = null);

        void DecryptFile(string inputFilePath, string outputFilePath, IProgress<int> progress = null);

        Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);

        Task DecryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            IProgress<int> progress = null,
            CancellationToken cancellationToken = default);
    }
}
