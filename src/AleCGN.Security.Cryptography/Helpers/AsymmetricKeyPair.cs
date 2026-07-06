namespace AleCGN.Security.Cryptography
{
    public class AsymmetricKeyPair
    {
        public AsymmetricKeyPair(string publicKeyPem, string privateKeyPem)
        {
            PublicKeyPem = publicKeyPem;
            PrivateKeyPem = privateKeyPem;
        }


        public string PublicKeyPem { get; }

        public string PrivateKeyPem { get; }
    }
}
