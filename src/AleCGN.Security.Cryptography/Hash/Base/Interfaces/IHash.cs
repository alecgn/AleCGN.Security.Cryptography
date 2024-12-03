using System;

namespace AleCGN.Security.Cryptography.Hash
{
    public interface IHash : IDisposable
    {
        string ComputeHash(byte[] data, int offset = 0, int count = 0);

        string ComputeTextHash(string text, int offset = 0, int count = 0);

        string ComputeFileHash(string filePath, long offset = 0L, long count = 0L);

        string VerifyHash(byte[] data, byte[] hash, int offset = 0, int count = 0);

        string VerifyTextHash(string text, string hash, int offset = 0, int count = 0);

        string VerifyFileHash(string filePath, byte[] hash, long offset = 0L, long count = 0L);

        string VerifyFileHash(string filePath, string hash, long offset = 0L, long count = 0L);
    }
}
