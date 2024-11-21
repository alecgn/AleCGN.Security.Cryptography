namespace ConsoleApp_Net8
{
    internal class Program
    {
        static void Main(string[] args)
        {
            AleCGN.Security.Cryptography.Encoders.IEncoder base64Encoder = new AleCGN.Security.Cryptography.Encoders.Base64Encoder();
            AleCGN.Security.Cryptography.ISymmetricKeyHelper symmetricKeyHelper = new AleCGN.Security.Cryptography.SymmetricKeyHelper(base64Encoder);
            // string base64Encoded256bitKey = symmetricKeyHelper.GenerateSecureRandom256BitEncodedKey(); // you should store the key as a base64 or hexadecimal encoded string for later use
            // AesGcmBase implementations, like AesGcm256, supports an encoded key in constructor overloads
            byte[] key256bit = symmetricKeyHelper.GenerateSecureRandom256BitKey();
            AleCGN.Security.Cryptography.Encryption.Algorithms.Aes.IAesGcm256 aesGcm256 = new AleCGN.Security.Cryptography.Encryption.Algorithms.Aes.AesGcm256(base64Encoder, key256bit);

            var textToEncrypt = "My super secret text! ;D";

            Console.WriteLine($"Text to encrypt: \"{textToEncrypt}\"");

            var encryptedText = aesGcm256.EncryptText(textToEncrypt);

            Console.WriteLine($"Encrypted text: \"{encryptedText}\"");

            var decryptedText = aesGcm256.DecryptText(encryptedText);

            Console.WriteLine($"Decrypted text: \"{decryptedText}\"");

            Console.ReadKey();
        }
    }
}
