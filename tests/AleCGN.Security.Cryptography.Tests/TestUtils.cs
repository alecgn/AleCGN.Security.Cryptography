using System;
using System.IO;
using System.Text;

namespace AleCGN.Security.Cryptography.Tests
{
    internal static class TestUtils
    {
        internal static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

        internal static byte[] RepeatedBytes(byte value, int count)
        {
            var bytes = new byte[count];

            for (var i = 0; i < count; i++)
            {
                bytes[i] = value;
            }

            return bytes;
        }

        internal static string CreateTempFile(string content)
        {
            var path = Path.Combine(Path.GetTempPath(), "alecgn-tests-" + Guid.NewGuid().ToString("N") + ".tmp");

            File.WriteAllText(path, content);

            return path;
        }

        internal static string CreateTempFile(byte[] content)
        {
            var path = Path.Combine(Path.GetTempPath(), "alecgn-tests-" + Guid.NewGuid().ToString("N") + ".tmp");

            File.WriteAllBytes(path, content);

            return path;
        }

        internal static string TempFilePath()
            => Path.Combine(Path.GetTempPath(), "alecgn-tests-" + Guid.NewGuid().ToString("N") + ".tmp");

        internal static void DeleteFiles(params string[] paths)
        {
            foreach (var path in paths)
            {
                try
                {
                    File.Delete(path);
                }
                catch
                {
                    // best effort cleanup
                }
            }
        }
    }
}
