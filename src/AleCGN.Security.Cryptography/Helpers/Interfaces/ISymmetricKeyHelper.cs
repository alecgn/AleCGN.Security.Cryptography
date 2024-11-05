namespace AleCGN.Security.Cryptography
{
    public interface ISymmetricKeyHelper
    {
        byte[] GenerateSecureRandom128BitKey();

        string GenerateSecureRandom128BitEncodedKey();

        byte[] GenerateSecureRandom192BitKey();

        string GenerateSecureRandom192BitEncodedKey();

        byte[] GenerateSecureRandom256BitKey();

        string GenerateSecureRandom256BitEncodedKey();
    }
}
