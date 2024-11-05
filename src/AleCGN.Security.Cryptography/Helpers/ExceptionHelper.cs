using System;

namespace AleCGN.Security.Cryptography.Helpers
{
    internal static class ExceptionHelper
    {
        internal static void ThrowFormattedArgumentException(string formatedMessage, string paramName)
        {
            throw new ArgumentException(string.Format(formatedMessage, paramName), paramName);
        }
    }
}
