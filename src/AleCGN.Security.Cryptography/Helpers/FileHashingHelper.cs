using AleCGN.Security.Cryptography.Constants;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.Helpers
{
    internal static class FileHashingHelper
    {
        internal static byte[] ComputeHash(
            HashAlgorithm hashAlgorithm,
            string filePath,
            int bufferSizeInKB,
            long offset,
            long count,
            Action<int> progressCallback)
        {
            var buffer = new byte[bufferSizeInKB * ConstantValues.BytesPerKilobyte];

            using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, buffer.Length, FileOptions.SequentialScan))
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

                    ReportProgress(total, remaining, ref percentageDone, progressCallback);
                }

                if (remaining > 0 || total == 0)
                {
                    hashAlgorithm.TransformFinalBlock(buffer, 0, 0);
                }

                return hashAlgorithm.Hash;
            }
        }

        internal static async Task<byte[]> ComputeHashAsync(
            HashAlgorithm hashAlgorithm,
            string filePath,
            int bufferSizeInKB,
            long offset,
            long count,
            IProgress<int> progress,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[bufferSizeInKB * ConstantValues.BytesPerKilobyte];

            using (var fileStream = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.Read, buffer.Length,
                FileOptions.SequentialScan | FileOptions.Asynchronous))
            {
                fileStream.Seek(offset, SeekOrigin.Begin);

                var total = (count == 0 ? fileStream.Length - offset : count);
                var remaining = total;
                var percentageDone = 0;

                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var bytesRead = await fileStream
                        .ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, remaining), cancellationToken)
                        .ConfigureAwait(false);

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

                    ReportProgress(total, remaining, ref percentageDone, progress is null ? (Action<int>)null : progress.Report);
                }

                if (remaining > 0 || total == 0)
                {
                    hashAlgorithm.TransformFinalBlock(buffer, 0, 0);
                }

                return hashAlgorithm.Hash;
            }
        }

        private static void ReportProgress(long total, long remaining, ref int percentageDone, Action<int> progressCallback)
        {
            if (progressCallback is null)
            {
                return;
            }

            var tmpPercentageDone = (int)((total - remaining) * 100 / total);

            if (tmpPercentageDone != percentageDone)
            {
                percentageDone = tmpPercentageDone;

                progressCallback(percentageDone);
            }
        }
    }
}
