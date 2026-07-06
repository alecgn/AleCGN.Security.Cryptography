using System;

namespace AleCGN.Security.Cryptography.Helpers
{
    internal static class ExceptionHelper
    {
        internal static void ThrowFormattedArgumentException(string formatedMessage, string paramName)
        {
            throw CreateFormattedArgumentException(formatedMessage, paramName);
        }

        internal static ArgumentException CreateFormattedArgumentException(string formatedMessage, string paramName)
        {
            return new ArgumentException(string.Format(formatedMessage, paramName), paramName);
        }
    }
}
