using System.Threading;
using System.Threading.Tasks;

namespace AleCGN.Security.Cryptography.KeyDerivation
{
    public interface IPasswordHasher
    {
        string HashPassword(string password);

        bool VerifyPassword(string password, string hashedPassword);

        bool NeedsRehash(string hashedPassword);

        Task<string> HashPasswordAsync(string password, CancellationToken cancellationToken = default);

        Task<bool> VerifyPasswordAsync(string password, string hashedPassword, CancellationToken cancellationToken = default);

        Task<bool> NeedsRehashAsync(string hashedPassword, CancellationToken cancellationToken = default);
    }
}
