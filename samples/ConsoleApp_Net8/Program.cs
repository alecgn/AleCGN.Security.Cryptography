using AleCGN.Security.Cryptography;
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;
using AleCGN.Security.Cryptography.Hash;

namespace ConsoleApp_Net8
{
    internal class Program
    {
        private static int _failures;

        static int Main()
        {
            IEncoder hexadecimalEncoder = new HexadecimalEncoder();
            IEncoder base64Encoder = new Base64Encoder();

            // Encoders
            Check("Hex encode", hexadecimalEncoder.Encode("abc") == "616263");
            Check("Hex decode roundtrip", hexadecimalEncoder.Decode("0x616263").SequenceEqual("abc"u8.ToArray()));
            Check("Base64 roundtrip", base64Encoder.Decode(base64Encoder.Encode("AleCGN")).SequenceEqual("AleCGN"u8.ToArray()));

            // Hash (known test vectors)
            using var md5 = new MD5(hexadecimalEncoder);
            using var sha256 = new SHA256(hexadecimalEncoder);

            Check("MD5(\"abc\")", md5.ComputeTextHash("abc", out _) == "900150983CD24FB0D6963F7D28E17F72");
            Check("SHA256(\"abc\")", sha256.ComputeTextHash("abc", out _) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
            Check("VerifyTextHash (match)", sha256.VerifyTextHash("abc", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
            Check("VerifyTextHash (mismatch)", !sha256.VerifyTextHash("abcd", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
            Check("ComputeTextHash with offset", sha256.ComputeTextHash("XXabc", out _, offset: 2) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

            // File hash
            var filePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-hash.txt");
            File.WriteAllText(filePath, "abc");

            md5.OnComputeFileHashProgressChanged += (_, percentage) => Console.WriteLine($"  file hash progress: {percentage}%");

            Check("File hash", md5.ComputeFileHash(filePath, out _) == "900150983CD24FB0D6963F7D28E17F72");
            Check("File hash (repeated call, same instance)", md5.ComputeFileHash(filePath, out _) == "900150983CD24FB0D6963F7D28E17F72");
            Check("VerifyFileHash", md5.VerifyFileHash(filePath, "900150983CD24FB0D6963F7D28E17F72"));

            var emptyFilePath = Path.Combine(Path.GetTempPath(), "alecgn-sample-empty.txt");
            File.WriteAllText(emptyFilePath, string.Empty);

            Check("Empty file hash", md5.ComputeFileHash(emptyFilePath, out _) == "D41D8CD98F00B204E9800998ECF8427E");

            // AES-GCM
            ISymmetricKeyHelper symmetricKeyHelper = new SymmetricKeyHelper(base64Encoder);
            var key256bit = symmetricKeyHelper.GenerateSecureRandom256BitKey();

            using (IAesGcm256 aesGcm256 = new AesGcm256(base64Encoder, key256bit))
            {
                var textToEncrypt = "My super secret text! ;D";
                var encryptedText = aesGcm256.EncryptText(textToEncrypt);
                var decryptedText = aesGcm256.DecryptText(encryptedText);

                Check("AES-GCM 256 roundtrip", decryptedText == textToEncrypt);

                aesGcm256.SetOrUpdateKey(symmetricKeyHelper.GenerateSecureRandom256BitEncodedKey());

                var reEncryptedText = aesGcm256.EncryptText(textToEncrypt);

                Check("AES-GCM 256 roundtrip after key update", aesGcm256.DecryptText(reEncryptedText) == textToEncrypt);
            }

            Console.WriteLine(_failures == 0 ? "All checks passed." : $"{_failures} check(s) FAILED.");

            return _failures;
        }

        private static void Check(string description, bool passed)
        {
            if (!passed)
            {
                _failures++;
            }

            Console.WriteLine($"[{(passed ? "PASS" : "FAIL")}] {description}");
        }
    }
}
