using AleCGN.Security.Cryptography.Resources;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using static AleCGN.Security.Cryptography.Helpers.ExceptionHelper;

namespace AleCGN.Security.Cryptography.Helpers
{
    internal static class PemKeyHelper
    {
        internal static AsymmetricKeyParameter ReadPublicKey(string publicKeyPem, string paramName)
        {
            var pemObject = ReadPemObject(publicKeyPem, paramName);

            if (pemObject is AsymmetricCipherKeyPair keyPair)
            {
                return keyPair.Public;
            }

            if (pemObject is AsymmetricKeyParameter keyParameter && !keyParameter.IsPrivate)
            {
                return keyParameter;
            }

            throw CreateFormattedArgumentException(LibraryResources.Validation_InvalidPemKey, paramName);
        }

        internal static AsymmetricKeyParameter ReadPrivateKey(string privateKeyPem, string paramName)
        {
            var pemObject = ReadPemObject(privateKeyPem, paramName);

            if (pemObject is AsymmetricCipherKeyPair keyPair)
            {
                return keyPair.Private;
            }

            if (pemObject is AsymmetricKeyParameter keyParameter && keyParameter.IsPrivate)
            {
                return keyParameter;
            }

            throw CreateFormattedArgumentException(LibraryResources.Validation_InvalidPemKey, paramName);
        }

        internal static string WritePem(object keyObject)
        {
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);

                pemWriter.WriteObject(keyObject);
                pemWriter.Writer.Flush();

                return stringWriter.ToString();
            }
        }

        private static object ReadPemObject(string pem, string paramName)
        {
            object pemObject;

            try
            {
                using (var stringReader = new StringReader(pem))
                {
                    pemObject = new PemReader(stringReader).ReadObject();
                }
            }
            catch
            {
                throw CreateFormattedArgumentException(LibraryResources.Validation_InvalidPemKey, paramName);
            }

            if (pemObject is null)
            {
                throw CreateFormattedArgumentException(LibraryResources.Validation_InvalidPemKey, paramName);
            }

            return pemObject;
        }
    }
}
