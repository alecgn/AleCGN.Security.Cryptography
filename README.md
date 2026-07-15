# AleCGN.Security.Cryptography [![Nuget version (AleCGN.Security.Cryptography)](https://img.shields.io/nuget/v/AleCGN.Security.Cryptography)](https://nuget.org/packages/AleCGN.Security.Cryptography)  

Easy-to-use, misuse-resistant cryptographic library for .NET. High-level, interface-based APIs over vetted primitives (native .NET cryptography and BouncyCastle), with safe defaults, self-contained payload formats and fixed-time verification everywhere.

```
dotnet add package AleCGN.Security.Cryptography
dotnet add package AleCGN.Security.Cryptography.DependencyInjection   # optional DI integration
```

## Contents

- [Supported frameworks and backends](#supported-frameworks-and-backends)
- [Design principles](#design-principles)
- [Sync and async APIs](#sync-and-async-apis)
- [Encoders](#encoders)
- [Hashing](#hashing)
- [HMAC (message authentication)](#hmac-message-authentication)
- [Key derivation](#key-derivation)
  - [PBKDF2](#pbkdf2)
  - [Argon2id](#argon2id)
  - [HKDF](#hkdf)
- [Password hashing (PasswordHasher)](#password-hashing-passwordhasher)
- [Authenticated encryption (AEAD)](#authenticated-encryption-aead)
  - [AES-GCM](#aes-gcm)
  - [ChaCha20-Poly1305](#chacha20-poly1305)
- [Password-based encryption](#password-based-encryption)
- [File encryption](#file-encryption)
- [Windows DPAPI (DataProtection)](#windows-dpapi-dataprotection)
- [Asymmetric cryptography](#asymmetric-cryptography)
  - [Key pair generation (PEM)](#key-pair-generation-pem)
  - [RSA-OAEP encryption](#rsa-oaep-encryption)
  - [Digital signatures (RSA-PSS and ECDSA)](#digital-signatures-rsa-pss-and-ecdsa)
- [Helpers](#helpers)
- [Dependency injection](#dependency-injection)
- [Payload format reference](#payload-format-reference)
- [Thread safety](#thread-safety)
- [Error handling](#error-handling)
- [Security notes](#security-notes)

---

## Supported frameworks and backends

The library multi-targets `netstandard2.0`, `netstandard2.1`, `net8.0` and `net10.0`. Consumers automatically get the best implementation available for their runtime — .NET 10 applications load a dedicated `net10.0` build (same modern code paths as `net8.0`, compiled and validated against the .NET 10 runtime):

| Feature            | netstandard2.0 (.NET Framework 4.6.1+, .NET Core 2.x) | netstandard2.1 (.NET Core 3.x, Mono, Xamarin)                    | net8.0 / net10.0                             |
| ------------------ | ----------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------- |
| AES-GCM            | BouncyCastle`GcmBlockCipher`                        | Native`System.Security.Cryptography.AesGcm` (spans, zero-copy) | Native`AesGcm` (hardware intrinsics)       |
| ChaCha20-Poly1305  | BouncyCastle                                          | BouncyCastle                                                     | BouncyCastle                                 |
| PBKDF2             | BouncyCastle`Pkcs5S2ParametersGenerator`            | `Rfc2898DeriveBytes`                                           | Static one-shot`Rfc2898DeriveBytes.Pbkdf2` |
| Argon2id           | BouncyCastle                                          | BouncyCastle                                                     | BouncyCastle                                 |
| HKDF               | BouncyCastle`HkdfBytesGenerator`                    | BouncyCastle                                                     | Native`System.Security.Cryptography.HKDF`  |
| Hash / HMAC        | Native                                                | Native                                                           | Native                                       |
| RSA / ECDSA / PEM  | BouncyCastle                                          | BouncyCastle                                                     | BouncyCastle                                 |
| Random             | Shared`RandomNumberGenerator` instance              | `RandomNumberGenerator.Fill`                                   | `RandomNumberGenerator.Fill`               |
| Fixed-time compare | Constant-time loop                                    | `CryptographicOperations.FixedTimeEquals`                      | `CryptographicOperations.FixedTimeEquals`  |

All payload formats are **byte-for-byte identical across frameworks**: data encrypted or signed on .NET Framework 4.8 decrypts and verifies on .NET 8 and vice versa (covered by cross-framework functional checks in the sample suite).

Dependencies: [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) 2.6.2, [System.Security.Cryptography.ProtectedData](https://www.nuget.org/packages/System.Security.Cryptography.ProtectedData) 10.0.9.

## Design principles

- **Interface-first.** Every service has an interface (`IAesGcm256`, `IPasswordHasher`, `ISHA256`, ...) for testability and DI.
- **Pluggable string encoding.** Classes that produce or consume strings take an [`IEncoder`](#encoders) in the constructor; the same operation can emit Base64, Base64Url, Base32 or hexadecimal without changing call sites.
- **Self-describing outputs.** Every encrypted payload, password hash and signature uses a canonical envelope that names the algorithm, format version and each field explicitly — nothing is ever inferred from byte positions or sizes. Text APIs emit PHC-style strings (`$aes256-gcm$v=1$<nonce>$<tag>$<ciphertext>`); binary APIs emit an equivalent tagged binary envelope with length-prefixed fields (see [Payload format reference](#payload-format-reference)). Everything needed to reverse the operation later (nonce, tag, salt, KDF parameters) travels inside the payload, and parameter upgrades never break old data.
- **Fixed-time verification.** All `Verify*` APIs (hash, HMAC, derived keys, passwords) compare in constant time to prevent timing attacks.
- **Defensive key handling.** Keys passed in are copied (caller mutations don't affect the instance); replaced or disposed keys are zeroed in memory.
- **Fail loudly on bad input.** Arguments are validated up front with descriptive `ArgumentException`s; authentication failures throw `CryptographicException` (or the BouncyCastle equivalent) rather than returning garbage.
- **Sync and async everywhere.** Every operation that performs I/O or non-trivial compute has an `*Async` counterpart accepting a `CancellationToken` (see [Sync and async APIs](#sync-and-async-apis)).

## Sync and async APIs

Every hash, HMAC, KDF, password-hashing, encryption, signing and key-generation operation is available in both forms. The async variants follow a consistent pattern:

- **I/O-bound operations** (file hashing/HMAC, file encryption) are *truly asynchronous*: files are opened with `FileOptions.Asynchronous` and read/written with `ReadAsync`/`WriteAsync`. The `CancellationToken` is observed between buffer reads/chunks, so cancellation is responsive even on multi-gigabyte files. `IProgress<int>` reports percentage progress.
- **CPU-bound operations** (KDF derivation, AEAD encryption, RSA/ECDSA operations, key pair generation) are *offloaded to the thread pool* (`Task.Run`), keeping UI threads and ASP.NET request threads free during expensive work — an Argon2id derivation or a 4096-bit RSA key generation can take from hundreds of milliseconds to seconds. The `CancellationToken` cancels the work if it has not started yet; once the underlying primitive is running it completes (crypto primitives are not interruptible mid-computation).
- **Methods with `out` parameters** get dedicated async result types instead: `HashResult`/`FileHashResult` (`EncodedHash` + `HashBytes`), `KeyDerivationResult` (`Key` + `Salt`) and `EncodedKeyDerivationResult` (`EncodedKey` + `EncodedSalt`).
- Exceptions from async methods (including validation errors) are delivered through the returned `Task`; cancellation surfaces as `OperationCanceledException`.

Deliberately sync-only: encoders, `SymmetricKeyHelper`, `CryptographyHelper` and `SetOrUpdateKey` — constant-time, allocation-only operations where an async wrapper would add overhead without ever unblocking anything.

```csharp
// Examples
HashResult hash = await sha256.ComputeTextHashAsync("abc", cancellationToken: ct);
KeyDerivationResult derived = await argon2id.DeriveKeyAsync(passwordBytes, ct);   // .Key + random .Salt
string phc = await passwordHasher.HashPasswordAsync(password, ct);
byte[] payload = await aes.EncryptDataAsync(data, associatedData, ct);
AsymmetricKeyPair pair = await rsaKeyPairHelper.GenerateKeyPairAsync(RsaKeySizes.KeySize4096Bits, ct);
```

---

## Encoders

Namespace: `AleCGN.Security.Cryptography.Encoders`

All encoders implement a single interface and are stateless (safe to share and reuse):

```csharp
public interface IEncoder
{
    string Encode(byte[] data);
    string Encode(string text);      // UTF-8 bytes of the text
    byte[] Decode(string encodedData);
}
```

| Class                  | Format                                                                                         | Typical use                                             |
| ---------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `Base64Encoder`      | Standard Base64 (RFC 4648 §4)                                                                 | General-purpose, storage, transport                     |
| `Base64UrlEncoder`   | URL-safe Base64, unpadded (RFC 4648 §5)                                                       | URLs, file names, JWT-like tokens, query strings        |
| `Base32Encoder`      | Base32, uppercase padded output (RFC 4648 §6); decoding accepts lowercase and missing padding | TOTP/2FA secrets, case-insensitive identifiers          |
| `HexadecimalEncoder` | Uppercase hex; decoding accepts lowercase and an optional`0x` prefix                         | Hash digests, debugging, interop with hex-based systems |

```csharp
IEncoder hex = new HexadecimalEncoder();
hex.Encode("abc");                   // "616263"
hex.Decode("0x616263");              // byte[] { 0x61, 0x62, 0x63 }

IEncoder b64url = new Base64UrlEncoder();
b64url.Encode(tokenBytes);           // no '+', '/', '=' — safe in URLs

IEncoder b32 = new Base32Encoder();
b32.Encode("foobar");                // "MZXW6YTBOI======"
b32.Decode("mzxw6ytboi");            // lowercase + unpadded accepted
```

Implementation notes: the hexadecimal encoder uses a lookup table and single-buffer conversion (no per-byte allocations); Base64 validation converts `FormatException` into a descriptive `ArgumentException`.

---

## Hashing

Namespace: `AleCGN.Security.Cryptography.Hash`

Classes: `MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512` — all inherit `HashBase` and implement `IHash` (plus a marker interface each: `IMD5`, `ISHA256`, ...). All five are available on **every** target framework.

```csharp
public interface IHash : IDisposable
{
    string ComputeHash(byte[] data, out byte[] hashBytes, int offset = 0, int count = 0);
    string ComputeTextHash(string text, out byte[] hashBytes, int offset = 0, int count = 0);
    string ComputeFileHash(string filePath, out byte[] hashBytes, int bufferSizeInKB = 64, long offset = 0, long count = 0);
    bool VerifyHash(byte[] data, byte[] hash, int offset = 0, int count = 0);
    bool VerifyTextHash(string text, string hash, int offset = 0, int count = 0);
    bool VerifyFileHash(string filePath, byte[] hash, long offset = 0, long count = 0);
    bool VerifyFileHash(string filePath, string hash, long offset = 0, long count = 0);

    // Async counterparts (CancellationToken everywhere; file overloads also take IProgress<int>)
    Task<HashResult> ComputeHashAsync(byte[] data, int offset = 0, int count = 0, CancellationToken cancellationToken = default);
    Task<HashResult> ComputeTextHashAsync(string text, int offset = 0, int count = 0, CancellationToken cancellationToken = default);
    Task<FileHashResult> ComputeFileHashAsync(string filePath, int bufferSizeInKB = 64, long offset = 0,
        long count = 0, IProgress<int> progress = null, CancellationToken cancellationToken = default);
    Task<bool> VerifyHashAsync(byte[] data, byte[] hash, int offset = 0, int count = 0, CancellationToken cancellationToken = default);
    Task<bool> VerifyTextHashAsync(string text, string hash, int offset = 0, int count = 0, CancellationToken cancellationToken = default);
    Task<bool> VerifyFileHashAsync(string filePath, byte[] hash, long offset = 0, long count = 0,
        IProgress<int> progress = null, CancellationToken cancellationToken = default);
    Task<bool> VerifyFileHashAsync(string filePath, string hash, long offset = 0, long count = 0,
        IProgress<int> progress = null, CancellationToken cancellationToken = default);
}
```

Semantics:

- The return value is the digest encoded with the injected `IEncoder`; the raw bytes come out via the `out` parameter (or `FileHashResult.HashBytes` in the async API).
- `offset`/`count` select a slice of the input; `count = 0` means "everything after `offset`".
- File hashing streams the file with a configurable buffer (default 64 KB), `FileShare.Read` and `FileOptions.SequentialScan` — constant memory for any file size. Progress is reported as an integer percentage via the `OnComputeFileHashProgressChanged` event (sync) or `IProgress<int>` (async).
- A `HashAlgorithm` instance is created and disposed **per operation**, so instances are reusable and thread-safe.
- All `Verify*` overloads use fixed-time comparison.

```csharp
using AleCGN.Security.Cryptography.Encoders;
using AleCGN.Security.Cryptography.Hash;

using var sha256 = new SHA256(new HexadecimalEncoder());

// Data / text
string digest = sha256.ComputeTextHash("abc", out byte[] raw);
// "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
bool ok = sha256.VerifyTextHash("abc", digest);

// Large file with progress + cancellation
var result = await sha256.ComputeFileHashAsync(@"C:\isos\image.iso",
    bufferSizeInKB: 256,
    progress: new Progress<int>(p => Console.Write($"\r{p}%")),
    cancellationToken: cts.Token);
Console.WriteLine(result.EncodedHash);

// Verify a downloaded file against a published checksum
bool intact = sha256.VerifyFileHash(@"C:\downloads\tool.zip", publishedSha256Hex);
```

**Use cases:** file integrity/checksum verification, content-addressed storage keys, deduplication, ETag generation, non-security fingerprinting (MD5/SHA1).

> ⚠️ MD5 and SHA-1 are broken for collision resistance. They are provided for interop and checksums only — never use them for signatures, certificates or password hashing.

---

## HMAC (message authentication)

Namespace: `AleCGN.Security.Cryptography.Hmac`

Classes: `HMACMD5`, `HMACSHA1`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512` — all inherit `HmacBase` and implement `IHmac`. The API mirrors the hash module (data/text/file, sync/async, fixed-time `Verify*`), plus key management:

```csharp
public interface IHmac : IDisposable
{
    void SetOrUpdateKey(byte[] key);
    void SetOrUpdateKey(string encodedKey);
    string ComputeHmac(byte[] data, out byte[] hmacBytes, int offset = 0, int count = 0);
    string ComputeTextHmac(string text, out byte[] hmacBytes, int offset = 0, int count = 0);
    string ComputeFileHmac(string filePath, out byte[] hmacBytes, int bufferSizeInKB = 64, long offset = 0, long count = 0);
    bool VerifyHmac(byte[] data, byte[] hmac, int offset = 0, int count = 0);
    bool VerifyTextHmac(string text, string encodedHmac, int offset = 0, int count = 0);
    bool VerifyFileHmac(string filePath, byte[] hmac, long offset = 0, long count = 0);
    bool VerifyFileHmac(string filePath, string encodedHmac, long offset = 0, long count = 0);

    // Async counterparts, mirroring IHash: ComputeHmacAsync / ComputeTextHmacAsync (Task<HashResult>),
    // ComputeFileHmacAsync (Task<FileHashResult>, IProgress<int>), VerifyHmacAsync / VerifyTextHmacAsync /
    // VerifyFileHmacAsync (Task<bool>) — all accepting a CancellationToken.
}
```

Constructors: `(IEncoder)`, `(IEncoder, byte[] key)`, `(IEncoder, string encodedKey)`. HMAC accepts keys of any non-zero length; a key at least as long as the digest output is recommended (use [`SymmetricKeyHelper`](#helpers)). Keys are defensively copied and zeroed on replacement/`Dispose`. Using an instance before setting a key throws `CryptographicException`.

```csharp
using AleCGN.Security.Cryptography.Hmac;

byte[] key = new SymmetricKeyHelper(new Base64Encoder()).GenerateSecureRandom256BitKey();
using var hmac = new HMACSHA256(new HexadecimalEncoder(), key);

// Sign an outgoing webhook payload
string signature = hmac.ComputeTextHmac(jsonPayload, out _);

// Verify an incoming webhook (fixed-time — safe against timing attacks)
bool authentic = hmac.VerifyTextHmac(receivedPayload, receivedSignatureHeader);

// Authenticate a file
string fileMac = hmac.ComputeFileHmac(@"C:\exports\report.csv", out _);
```

**Use cases:** webhook signatures, API request signing, cookie/token integrity, authenticating files or messages between services that share a secret. For encrypting *and* authenticating in one step, prefer [AES-GCM](#aes-gcm).

---

## Key derivation

Namespace: `AleCGN.Security.Cryptography.KeyDerivation`

Three KDFs, three jobs:

| Class        | Algorithm           | Input                                 | Use when                                                |
| ------------ | ------------------- | ------------------------------------- | ------------------------------------------------------- |
| `Pbkdf2`   | PBKDF2 (RFC 8018)   | Low-entropy password                  | FIPS-constrained environments, interop                  |
| `Argon2id` | Argon2id (RFC 9106) | Low-entropy password                  | Best-practice password hashing/derivation (memory-hard) |
| `Hkdf`     | HKDF (RFC 5869)     | **Already-strong** key material | Expanding a master key into sub-keys                    |

### PBKDF2

```csharp
// Configuration: PRF, iterations, salt size (bytes), derived key size (bytes)
var config = new Pbkdf2Configuration(Pbkdf2PseudoRandomFunction.HMACSHA256,
    iterations: 600_000, saltSize: 16, derivedKeySize: 32);

IPbkdf2 pbkdf2 = new Pbkdf2(new Base64Encoder());          // = Pbkdf2Configuration.Default (above values)
IPbkdf2 custom = new Pbkdf2(new Base64Encoder(), config);

// Derive with a generated random salt (out param)
byte[] key = pbkdf2.DeriveKey(passwordBytes, out byte[] salt);
string encodedKey = pbkdf2.DeriveTextKey("password", out string encodedSalt);

// Derive with a known salt (e.g. re-deriving for verification / interop)
byte[] again = pbkdf2.DeriveKey(passwordBytes, salt);

// Fixed-time verification
bool match = pbkdf2.VerifyKey(passwordBytes, salt, expectedKey);
bool match2 = pbkdf2.VerifyTextKey("password", encodedSalt, encodedKey);

// Async (out params become result objects)
KeyDerivationResult result = await pbkdf2.DeriveKeyAsync(passwordBytes, ct);          // .Key + .Salt
EncodedKeyDerivationResult text = await pbkdf2.DeriveTextKeyAsync("password", ct);    // .EncodedKey + .EncodedSalt
byte[] key2 = await pbkdf2.DeriveKeyAsync(passwordBytes, salt, ct);
bool ok = await pbkdf2.VerifyKeyAsync(passwordBytes, salt, expectedKey, ct);
```

- `Pbkdf2PseudoRandomFunction`: `HMACSHA1`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512`.
- Defaults follow the OWASP recommendation (PBKDF2-HMAC-SHA256, 600,000 iterations).
- Configured salt size must be ≥ 8 bytes (RFC 8018); externally supplied salts are accepted at any non-zero length for interop.

### Argon2id

Memory-hard KDF — the current best practice for passwords. Backed by BouncyCastle on all frameworks (identical output everywhere).

```csharp
// memorySizeInKB, iterations, parallelism, saltSize, derivedKeySize
var config = new Argon2idConfiguration(19_456, 2, 1, 16, 32);   // = Argon2idConfiguration.Default (OWASP)

IArgon2id argon2 = new Argon2id(new Base64Encoder());           // default config
byte[] key = argon2.DeriveKey(passwordBytes, out byte[] salt);
bool ok = argon2.VerifyKey(passwordBytes, salt, key);           // fixed-time
```

API shape is identical to `Pbkdf2` (`DeriveKey`/`DeriveTextKey`/`VerifyKey`/`VerifyTextKey` plus the `*Async` counterparts with `CancellationToken`). Tune memory/iterations to your hardware budget; OWASP's minimum baseline is 19 MiB / t=2 / p=1. Argon2id is deliberately expensive — prefer `DeriveKeyAsync` on UI/server threads.

### HKDF

Expands strong input key material (a master key, an ECDH shared secret, ...) into any number of purpose-bound sub-keys. **Not for passwords** — it is not designed to be slow.

```csharp
IHkdf hkdf = new Hkdf(new Base64Encoder());                          // HMAC-SHA256
IHkdf sha512 = new Hkdf(new Base64Encoder(), HashAlgorithmKind.SHA512);

byte[] encryptionKey = hkdf.DeriveKey(masterKey, derivedKeySize: 32,
    salt: appSalt,                                   // optional, recommended
    info: "encryption"u8.ToArray());                 // context binding — different info => independent key

byte[] macKey = hkdf.DeriveKey(masterKey, 32, appSalt, "mac"u8.ToArray());

string textKey = hkdf.DeriveTextKey("master-material", 32, salt: "app", info: "cache-signing");
byte[] asyncKey = await hkdf.DeriveKeyAsync(masterKey, 32, appSalt, infoBytes, ct);
```

**Use case:** one stored master secret, many independent keys — one per purpose (`info`) — with domain separation guaranteed by the KDF.

---

## Password hashing (PasswordHasher)

Namespace: `AleCGN.Security.Cryptography.KeyDerivation`

The recommended way to **store and verify user passwords**. Produces a single self-contained string in the PHC format — algorithm, version, parameters, salt and hash all embedded:

```
$argon2id$v=19$m=19456,t=2,p=1$<salt-b64>$<hash-b64>
$pbkdf2-sha256$i=600000$<salt-b64>$<hash-b64>
```

```csharp
public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hashedPassword);   // fixed-time
    bool NeedsRehash(string hashedPassword);

    Task<string> HashPasswordAsync(string password, CancellationToken cancellationToken = default);
    Task<bool> VerifyPasswordAsync(string password, string hashedPassword, CancellationToken cancellationToken = default);
    Task<bool> NeedsRehashAsync(string hashedPassword, CancellationToken cancellationToken = default);
}
```

```csharp
IPasswordHasher hasher = new PasswordHasher();                     // Argon2id, OWASP defaults
// or: new PasswordHasher(new Argon2idConfiguration(...));
// or: new PasswordHasher(new Pbkdf2Configuration(...));           // PBKDF2 mode (e.g. FIPS)

// Registration
string stored = hasher.HashPassword(newUserPassword);              // store this single string

// Login
if (hasher.VerifyPassword(typedPassword, stored))
{
    // Parameter upgrade path: rehash transparently after a successful login
    if (hasher.NeedsRehash(stored))
    {
        stored = hasher.HashPassword(typedPassword);               // persist the new value
    }
}
```

Key properties:

- `VerifyPassword` parses the stored string and derives with the **stored** parameters — verification keeps working forever, even after you change the configured algorithm or costs.
- `NeedsRehash` returns `true` when the stored hash was produced with anything different from the current configuration (different algorithm, iterations, memory, salt/hash sizes) — the hook for gradual migration, including PBKDF2 → Argon2id.
- Malformed strings throw a descriptive `ArgumentException`; salts/hashes are unpadded Base64 per the PHC convention (interoperable with passlib and friends).

---

## Authenticated encryption (AEAD)

Both AEAD ciphers share the same conventions:

- **Self-describing output:** text APIs return `$<algorithm>$v=1$<nonce>$<tag>$<ciphertext>` (unpadded Base64 fields); binary APIs return the equivalent tagged binary envelope. Algorithm, version and every field are explicit — a payload produced by `AesGcm128` is rejected by `AesGcm256` with a clear format error instead of a confusing authentication failure.
- A **fresh random nonce** is generated per encryption (CSPRNG). You never manage nonces manually, which removes the classic catastrophic GCM misuse (nonce reuse).
- Optional **associated data (AAD)**: authenticated but not encrypted. Decryption fails if the AAD differs.
- `SetOrUpdateKey(byte[] | string)` swaps the key; old key material is zeroed. `Dispose()` zeroes the key.
- Tampering (any bit of ciphertext, tag, nonce or AAD) ⇒ authentication exception, never corrupted plaintext.

### AES-GCM

Namespace: `AleCGN.Security.Cryptography.Encryption.Algorithms.Aes`

Classes: `AesGcm128`, `AesGcm192`, `AesGcm256` (key sizes 16/24/32 bytes), implementing `IAesGcm128/192/256 : IAesGcmBase`:

```csharp
public interface IAesGcmBase : IEncryptionOperations, IDisposable
{
    byte[] EncryptData(byte[] data);                                   // from IEncryptionOperations
    byte[] EncryptData(byte[] data, byte[] associatedData);
    string EncryptText(string text);
    string EncryptText(string text, byte[] associatedData);
    byte[] DecryptData(byte[] encryptedDataWithMetadata);
    byte[] DecryptData(byte[] encryptedDataWithMetadata, byte[] associatedData);
    string DecryptText(string encryptedTextWithMetadata);
    string DecryptText(string encryptedTextWithMetadata, byte[] associatedData);

    // Async counterparts: every method above has an *Async version with a CancellationToken,
    // with and without associatedData (EncryptDataAsync, EncryptTextAsync, DecryptDataAsync, DecryptTextAsync).

    void SetOrUpdateKey(byte[] key);
    void SetOrUpdateKey(string encodedKey);
}
```

```csharp
using AleCGN.Security.Cryptography.Encryption.Algorithms.Aes;

var encoder = new Base64Encoder();
byte[] key = new SymmetricKeyHelper(encoder).GenerateSecureRandom256BitKey();

using IAesGcm256 aes = new AesGcm256(encoder, key);
// also: new AesGcm256(encoder)                    -> call SetOrUpdateKey later
// also: new AesGcm256(encoder, encodedKeyString)  -> key stored as Base64/hex/etc.

// Text in, encoded text out (encoding = injected IEncoder)
string encrypted = aes.EncryptText("sensitive data");
string decrypted = aes.DecryptText(encrypted);

// Binding ciphertext to a context with AAD:
byte[] context = Encoding.UTF8.GetBytes($"user:{userId}|field:ssn");
byte[] payload = aes.EncryptData(ssnBytes, context);
// Moving this payload to another user's row makes decryption fail:
byte[] original = aes.DecryptData(payload, context);

// Async variants for large payloads / responsive threads:
byte[] payloadAsync = await aes.EncryptDataAsync(ssnBytes, context, ct);
string textAsync = await aes.DecryptTextAsync(encrypted, ct);
```

**Use cases:** encrypting database columns, secrets at rest, tokens, cache entries, message payloads. AAD is the right tool to bind a ciphertext to its owner/purpose (row id, tenant, field name) without storing extra data.

### ChaCha20-Poly1305

Namespace: `AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20`

`ChaCha20Poly1305` (RFC 8439), 256-bit key only, implementing `IChaCha20Poly1305` — the exact same API shape and payload layout as AES-GCM. Backed by BouncyCastle on all frameworks, so it works everywhere with identical output (no OS/hardware dependency).

```csharp
using AleCGN.Security.Cryptography.Encryption.Algorithms.ChaCha20;

using var chacha = new ChaCha20Poly1305(encoder, key256);
string encrypted = chacha.EncryptText("secret", "context"u8.ToArray());
string decrypted = chacha.DecryptText(encrypted, "context"u8.ToArray());
```

**When to prefer it over AES-GCM:** environments without AES hardware acceleration (older ARM/mobile/embedded), constant-time software guarantees, or protocol interop (TLS 1.3, WireGuard, age).

---

## Password-based encryption

Namespace: `AleCGN.Security.Cryptography.Encryption.PasswordBased`

“Encrypt this with this password” in one call: PBKDF2 derives a 256-bit key, AES-GCM-256 encrypts, and the output is fully self-describing — `$pbe-aes256-gcm$v=1$pbkdf2-sha256,i=600000$<salt>$<nonce>$<tag>$<ciphertext>` — with the KDF parameters and salt **bound as associated data**: tampering with the stored parameters invalidates the ciphertext.

```csharp
public interface IPasswordBasedEncryption
{
    byte[] EncryptData(byte[] data, string password);
    string EncryptText(string text, string password);
    byte[] DecryptData(byte[] encryptedDataWithMetadata, string password);
    string DecryptText(string encryptedTextWithMetadata, string password);

    // + EncryptDataAsync / EncryptTextAsync / DecryptDataAsync / DecryptTextAsync (CancellationToken) —
    // recommended, since every call runs a full PBKDF2 derivation.
}
```

```csharp
using AleCGN.Security.Cryptography.Encryption.PasswordBased;

IPasswordBasedEncryption pbe = new PasswordBasedEncryption(new Base64Encoder());
// or with custom KDF cost: new PasswordBasedEncryption(encoder, new Pbkdf2Configuration(...))

string vault = pbe.EncryptText("my API token", masterPassword);
string token = pbe.DecryptText(vault, masterPassword);       // wrong password => CryptographicException
```

Decryption reads the KDF parameters from the payload itself, so **payloads created with older configurations keep decrypting** after you raise the iteration count. The derived key is zeroed after each operation.

**Use cases:** password-protected exports/backups, "remember this locally" vaults, config secrets protected by an operator passphrase.

---

## File encryption

Namespace: `AleCGN.Security.Cryptography.Encryption.Files`

Streaming, chunked encryption on top of any `IAesGcmBase` — files of any size with constant memory. Each chunk is an independent AES-GCM payload whose AAD binds the file id, the chunk index and a final-chunk flag, so **reordering, truncating, duplicating or dropping chunks makes decryption fail**.

```csharp
public interface IFileEncryption
{
    void EncryptFile(string inputFilePath, string outputFilePath, IProgress<int> progress = null);
    void DecryptFile(string inputFilePath, string outputFilePath, IProgress<int> progress = null);
    Task EncryptFileAsync(string inputFilePath, string outputFilePath,
        IProgress<int> progress = null, CancellationToken cancellationToken = default);
    Task DecryptFileAsync(string inputFilePath, string outputFilePath,
        IProgress<int> progress = null, CancellationToken cancellationToken = default);
}
```

```csharp
using AleCGN.Security.Cryptography.Encryption.Files;

using IAesGcm256 aes = new AesGcm256(new Base64Encoder(), key);
IFileEncryption files = new FileEncryption(aes);              // default chunk: 1 MB
// or: new FileEncryption(aes, chunkSizeInKB: 4096)

await files.EncryptFileAsync(@"D:\backups\db.bak", @"D:\backups\db.bak.enc",
    progress: new Progress<int>(p => Console.Write($"\r{p}%")),
    cancellationToken: cts.Token);

await files.DecryptFileAsync(@"D:\backups\db.bak.enc", @"D:\backups\db.bak.restored");
```

Details: decryption reads the chunk size from the file header (an instance configured differently still decrypts any file); a chunk flagged "last" must actually be the last (and must exist) or decryption fails; empty input files are rejected. See the exact byte layout in the [format reference](#payload-format-reference).

**Use cases:** encrypted backups, large export files, media at rest — anywhere loading the whole file in memory is not an option.

---

## Windows DPAPI (DataProtection)

Namespace: `AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged`

Wrapper over Windows `ProtectedData` (DPAPI): the **operating system owns the key**, removing key management entirely. Windows-only (annotated `[SupportedOSPlatform("windows")]` on .NET 8; throws `PlatformNotSupportedException` elsewhere).

```csharp
using AleCGN.Security.Cryptography.Encryption.WindowsSelfManaged;

var dp = new DataProtection(new Base64Encoder(), DataProtectionConfiguration.Default);
// Default = no extra entropy, DataProtectionScope.LocalMachine
// or: new DataProtectionConfiguration(optionalEntropy: extraSecretBytes, DataProtectionScope.CurrentUser)

string protectedValue = dp.EncryptText("connection string");
string plain = dp.DecryptText(protectedValue);
// Async: EncryptDataAsync / EncryptTextAsync / DecryptDataAsync / DecryptTextAsync
```

- `DataProtectionScope.CurrentUser`: only the same Windows user can decrypt.
- `DataProtectionScope.LocalMachine`: any process on the same machine can decrypt — combine with `optionalEntropy` (an app-specific secret required again at decryption) to restrict it.

**Use cases:** protecting local configuration secrets, cached credentials and connection strings on Windows services/desktop apps without managing keys.

---

## Asymmetric cryptography

Backed by BouncyCastle on all frameworks; keys travel as **PEM strings**.

### Key pair generation (PEM)

Namespace: `AleCGN.Security.Cryptography` (helpers live alongside `SymmetricKeyHelper`)

```csharp
// RSA — RsaKeySizes.KeySize2048Bits (default) | KeySize3072Bits | KeySize4096Bits
AsymmetricKeyPair rsaPair = new RsaKeyPairHelper().GenerateKeyPair(RsaKeySizes.KeySize2048Bits);

// ECDSA — EcdsaCurves.NistP256 (default) | NistP384 | NistP521
AsymmetricKeyPair ecPair = new EcdsaKeyPairHelper().GenerateKeyPair(EcdsaCurves.NistP256);

// RSA key generation is expensive (hundreds of ms to seconds for 4096-bit) — prefer async:
AsymmetricKeyPair pair = await new RsaKeyPairHelper().GenerateKeyPairAsync(RsaKeySizes.KeySize4096Bits, ct);

rsaPair.PublicKeyPem;    // "-----BEGIN PUBLIC KEY----- ..."
rsaPair.PrivateKeyPem;   // "-----BEGIN RSA PRIVATE KEY----- ..." — store securely!
```

PEM parsing is lenient about what you pass: a private-key PEM also satisfies a `publicKeyPem` parameter (the public half is extracted). Invalid PEM throws a descriptive `ArgumentException`.

### RSA-OAEP encryption

Namespace: `AleCGN.Security.Cryptography.Encryption.Algorithms.Rsa`

```csharp
var rsa = new RsaOaepEncryption(new Base64Encoder(),
    publicKeyPem:  rsaPair.PublicKeyPem,     // needed for Encrypt*
    privateKeyPem: rsaPair.PrivateKeyPem,    // needed for Decrypt*
    oaepDigest:    HashAlgorithmKind.SHA256); // default

string encrypted = rsa.EncryptText("an AES key or small secret");
string plain = rsa.DecryptText(encrypted);

// Async: EncryptDataAsync / EncryptTextAsync / DecryptDataAsync / DecryptTextAsync (CancellationToken)
string encryptedAsync = await rsa.EncryptTextAsync("secret", ct);
```

RSA encrypts **small payloads only**. Maximum plaintext with OAEP-SHA256:

| Key size | Max plaintext |
| -------- | ------------- |
| 2048-bit | 190 bytes     |
| 3072-bit | 318 bytes     |
| 4096-bit | 446 bytes     |

**Standard pattern (hybrid encryption):** generate a random AES-256 key, encrypt the data with [AES-GCM](#aes-gcm), encrypt the AES key with RSA-OAEP, ship both.

### Digital signatures (RSA-PSS and ECDSA)

Namespace: `AleCGN.Security.Cryptography.Signatures`

`RsaPssSigner` and `EcdsaSigner` share `DigitalSignerBase` / `IDigitalSigner`:

```csharp
public interface IDigitalSigner
{
    byte[] SignData(byte[] data);                                  // requires private key
    string SignText(string text);
    bool VerifySignature(byte[] data, byte[] signature);           // requires public key
    bool VerifyTextSignature(string text, string encodedSignature);

    Task<byte[]> SignDataAsync(byte[] data, CancellationToken cancellationToken = default);
    Task<string> SignTextAsync(string text, CancellationToken cancellationToken = default);
    Task<bool> VerifySignatureAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default);
    Task<bool> VerifyTextSignatureAsync(string text, string encodedSignature, CancellationToken cancellationToken = default);
}
```

```csharp
using AleCGN.Security.Cryptography.Signatures;

// Signing side — private key
var signer = new RsaPssSigner(new Base64Encoder(), privateKeyPem: rsaPair.PrivateKeyPem);
string signature = signer.SignText(documentJson);

// Verifying side — public key only
var verifier = new RsaPssSigner(new Base64Encoder(), publicKeyPem: rsaPair.PublicKeyPem);
bool authentic = verifier.VerifyTextSignature(documentJson, signature);

// ECDSA is identical (smaller keys/signatures, faster):
var ecdsa = new EcdsaSigner(new Base64Encoder(), ecPair.PrivateKeyPem, ecPair.PublicKeyPem,
    hashAlgorithmKind: HashAlgorithmKind.SHA256);  // SHA1/256/384/512
```

Malformed signatures return `false` from `Verify*` (they never throw); missing keys throw `CryptographicException`. RSA-PSS signatures are randomized (two signatures of the same data differ — both verify).

**Use cases:** signing documents/licenses/manifests, verifying update packages, service-to-service authenticity where the verifier must not hold a secret (unlike HMAC).

---

## Helpers

Namespace: `AleCGN.Security.Cryptography` / `AleCGN.Security.Cryptography.Helpers`

```csharp
// Symmetric key generation (CSPRNG), raw or encoded with the injected IEncoder
ISymmetricKeyHelper keys = new SymmetricKeyHelper(new Base64Encoder());
byte[] k128 = keys.GenerateSecureRandom128BitKey();
byte[] k192 = keys.GenerateSecureRandom192BitKey();
byte[] k256 = keys.GenerateSecureRandom256BitKey();
string k256Encoded = keys.GenerateSecureRandom256BitEncodedKey();   // store/transport friendly

// Lower-level utilities
byte[] nonce = CryptographyHelper.GenerateSecureRandomBytes(12);    // any length, CSPRNG
bool equal = CryptographyHelper.FixedTimeEquals(mac1, mac2);        // timing-attack-safe comparison
```

`FixedTimeEquals` runs in time dependent only on length — use it whenever comparing MACs, hashes or derived keys yourself.

---

## Dependency injection

Package: `AleCGN.Security.Cryptography.DependencyInjection` (targets `netstandard2.0`, `net8.0` and `net10.0`)

One call registers everything as singletons:

```csharp
using AleCGN.Security.Cryptography.DependencyInjection;

services.AddAleCGNCryptography(options =>
{
    options.Encoder = EncoderKind.Base64;            // Base64 | Base64Url | Base32 | Hexadecimal
    options.AesGcm256Key = key;                      // register IAesGcm256 already keyed
    options.HmacKey = hmacKey;                       // register IHMAC* already keyed
    options.Pbkdf2Configuration  = Pbkdf2Configuration.Default;
    options.Argon2idConfiguration = Argon2idConfiguration.Default;
    options.UsePbkdf2ForPasswordHashing = false;     // IPasswordHasher: Argon2id (default) or PBKDF2
    options.RsaPublicKeyPem = pubPem;                // keys for IRsaOaepEncryption / IRsaPssSigner
    options.RsaPrivateKeyPem = privPem;
    options.EcdsaPublicKeyPem = ecPubPem;            // keys for IEcdsaSigner
    options.EcdsaPrivateKeyPem = ecPrivPem;
    options.DataProtectionConfiguration = DataProtectionConfiguration.Default; // opt-in, Windows-only
    options.FileEncryptionChunkSizeInKB = 1024;
});
```

| Service                                                                 | Notes                                                                                             |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `IEncoder`                                                            | Per`options.Encoder`; injected into every other service                                         |
| `IMD5`, `ISHA1`, `ISHA256`, `ISHA384`, `ISHA512`              | Always registered                                                                                 |
| `IHMACMD5` ... `IHMACSHA512`                                        | Keyed when`HmacKey` is set, keyless otherwise                                                   |
| `IAesGcm128/192/256`, `IChaCha20Poly1305`                           | Keyed when the corresponding key option is set, keyless otherwise (`SetOrUpdateKey` before use) |
| `IPbkdf2`, `IArgon2id`, `IHkdf`, `IPasswordHasher`              | Use the configured`Pbkdf2Configuration`/`Argon2idConfiguration`                               |
| `IPasswordBasedEncryption`, `IFileEncryption`                       | `IFileEncryption` uses the registered `IAesGcm256`                                            |
| `ISymmetricKeyHelper`, `IRsaKeyPairHelper`, `IEcdsaKeyPairHelper` | Always registered                                                                                 |
| `IRsaOaepEncryption`, `IRsaPssSigner`, `IEcdsaSigner`             | Registered with the configured PEM keys (may be keyless)                                          |
| `IDataProtection`                                                     | Only when`DataProtectionConfiguration` is set (Windows)                                         |

```csharp
public class UserService(IPasswordHasher passwordHasher, IAesGcm256 aes)
{
    public void Register(string password) => Save(passwordHasher.HashPassword(password));
    public string ProtectSsn(string ssn) => aes.EncryptText(ssn);
}
```

---

## Payload format reference

Every payload produced by the library is **self-describing**: the algorithm, format version and each field are explicit — nothing is inferred from byte positions or sizes. There is one canonical envelope with two representations.

### String envelope (all `*Text` APIs and `SignText`)

PHC-style, with **unpadded Base64** fields (fixed encoding, independent of the injected `IEncoder`):

```
$<algorithm>$v=1$[<parameters>$]<field1>$<field2>$...
```

| Algorithm | Format |
|---|---|
| AES-GCM | `$aes128-gcm\|aes192-gcm\|aes256-gcm$v=1$<nonce>$<tag>$<ciphertext>` |
| ChaCha20-Poly1305 | `$chacha20-poly1305$v=1$<nonce>$<tag>$<ciphertext>` |
| Password-based encryption | `$pbe-aes256-gcm$v=1$pbkdf2-<sha1\|sha256\|sha384\|sha512>,i=<iterations>$<salt>$<nonce>$<tag>$<ciphertext>` |
| RSA-OAEP | `$rsa-oaep-<digest>$v=1$<ciphertext>` |
| Windows DPAPI | `$dpapi$v=1$<protected-blob>` |
| RSA-PSS signature | `$rsa-pss-<digest>$v=1$<signature>` |
| ECDSA signature | `$ecdsa-<digest>$v=1$<signature>` |

### Binary envelope (all `*Data` APIs and `SignData`)

The same information in tagged binary form. All multi-byte integers are **little-endian**:

```
+-----------+--------+---------------+----------------+   +--------------------+---------------+
| "ACGN"(4) | ver(1) | algorithm(1)  | field count(1) |   | field length(4 LE) | field bytes   |  ... per field
+-----------+--------+---------------+----------------+   +--------------------+---------------+
```

| Algorithm id | Algorithm | Fields (in order) |
|---|---|---|
| 1 / 2 / 3 | aes128-gcm / aes192-gcm / aes256-gcm | nonce(12), tag(16), ciphertext |
| 4 | chacha20-poly1305 | nonce(12), tag(16), ciphertext |
| 5 | pbe-aes256-gcm | kdf = prf(1)+iterations(4), salt, nonce(12), tag(16), ciphertext |
| 6 | rsa-oaep | digest(1), ciphertext |
| 7 | dpapi | protected blob |
| 8 | rsa-pss | digest(1), signature |
| 9 | ecdsa | digest(1), signature |

Parsing validates magic, version, algorithm id, field count and every field length (including trailing bytes); any mismatch throws a descriptive `ArgumentException` — a payload from the wrong algorithm/key size is rejected by format, never by garbled output. String and binary payloads carry identical fields, so either form can be reconstructed from the other.

**Password-based encryption AAD:** the canonical byte sequence `version(1) ‖ algorithm(1) ‖ prf(1) ‖ iterations(4 LE) ‖ salt` is bound as associated data — identical for payloads produced via the string and binary APIs; modifying any KDF parameter invalidates the tag.

### Encrypted file (chunked)

```
header:  +-----------+--------+------------+--------------+
         | "ACFE"(4) | ver(1) | fileId(8)  | chunkSize(4) |
         +-----------+--------+------------+--------------+     ver = 2
chunk:   +-------------+-------------------------------------+
         | length(4)   | AEAD binary envelope (see above)    |   ... repeated
         +-------------+-------------------------------------+
AAD per chunk: fileId(8) ‖ chunkIndex(4 LE) ‖ isLastChunk(1)
```

### Password hash (PHC string)

```
$argon2id$v=19$m=<KB>,t=<iters>,p=<lanes>$<salt-b64-unpadded>$<hash-b64-unpadded>
$pbkdf2-<sha1|sha256|sha384|sha512>$i=<iterations>$<salt-b64-unpadded>$<hash-b64-unpadded>
```

### Deliberately plain (no envelope)

Hash digests, HMAC values, derived keys and generated keys are **single opaque fields** — there is no positional ambiguity to describe, and they must interoperate with external systems (published `SHA256SUMS`, webhook signature headers, keys fed into other tools). They are returned encoded with the injected `IEncoder`, exactly as before.

---

## Thread safety

| Component                                              | Thread-safe?           | Notes                                                                      |
| ------------------------------------------------------ | ---------------------- | -------------------------------------------------------------------------- |
| Encoders                                               | ✅                     | Stateless                                                                  |
| Hash classes (`SHA256`, ...)                         | ✅                     | Algorithm instance created per operation                                   |
| HMAC classes                                           | ✅ for compute/verify  | `SetOrUpdateKey`/`Dispose` must not race with operations               |
| `Pbkdf2`, `Argon2id`, `Hkdf`, `PasswordHasher` | ✅                     | Stateless per operation                                                    |
| AES-GCM classes                                        | ❌                     | Shared cipher state — use one instance per thread or synchronize          |
| `ChaCha20Poly1305`                                   | ✅ for encrypt/decrypt | Cipher created per operation; key updates must not race                    |
| `PasswordBasedEncryption`                            | ✅                     | Creates its AES instance per operation                                     |
| `FileEncryption`                                     | ❌                     | Inherits the AES-GCM instance's constraints                                |
| Key pair helpers, signers,`RsaOaepEncryption`        | ✅                     | Signer/engine created per operation; keys are immutable after construction |

---

## Error handling

| Situation                                                                                                         | Exception                                                                                                                                                                                    |
| ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Null/empty/whitespace argument, invalid encoded string, malformed PHC hash, corrupted payload header, invalid PEM | `ArgumentException` (message names the parameter)                                                                                                                                          |
| File not found                                                                                                    | `FileNotFoundException`                                                                                                                                                                    |
| Operating without a key / missing PEM key                                                                         | `CryptographicException`                                                                                                                                                                   |
| Authentication failure (wrong key/password/AAD, tampering, truncation)                                            | `CryptographicException` on native paths; `Org.BouncyCastle.Crypto.InvalidCipherTextException` on BouncyCastle paths — catch `Exception` or both when handling "wrong password" flows |
| Cancellation of async file APIs                                                                                   | `OperationCanceledException`                                                                                                                                                               |
| DPAPI on non-Windows                                                                                              | `PlatformNotSupportedException`                                                                                                                                                            |

`Verify*` methods return `false` for mismatches (and for malformed signatures) — they only throw for invalid *arguments*.

---

## Security notes

- **Choosing an algorithm:** user passwords → `PasswordHasher` (Argon2id). Encrypt with a password → `PasswordBasedEncryption`. Encrypt with a key → `AesGcm256` (or `ChaCha20Poly1305` without AES hardware). Sub-keys from a master key → `Hkdf`. Integrity with a shared secret → `HMACSHA256`. Integrity verifiable by anyone → signatures. Large data with a public key → hybrid (AES-GCM + RSA-OAEP for the AES key).
- **Nonces are handled for you** — random 12-byte nonce per AEAD encryption. With random nonces, keep well below ~2³² encryptions per key (NIST SP 800-38D); rotate keys with `SetOrUpdateKey` if you approach that volume.
- **Key storage is out of scope:** protect keys with DPAPI (Windows), a KMS/HSM, or at minimum OS-level ACLs. The library zeroes its internal key copies on replacement/dispose, but the arrays *you* hold are your responsibility.
- **MD5/SHA-1/HMAC-MD5** exist for interop and checksums only.
- **AAD is authenticated, not encrypted** — never put secrets in associated data.
- Verification of hashes, MACs, derived keys and passwords is **always fixed-time** in this library; keep it that way in your own code by using `CryptographyHelper.FixedTimeEquals`.

---

## Building, testing and releasing

```
dotnet build src/AleCGN.Security.Cryptography/AleCGN.Security.Cryptography.csproj -c Release
dotnet test  tests/AleCGN.Security.Cryptography.Tests/AleCGN.Security.Cryptography.Tests.csproj -c Release
```

The test suite (xUnit, 221 tests per framework) validates the implementations against official test vectors — RFC 4231/2202 (HMAC), RFC 5869 (HKDF), RFC 6070 (PBKDF2), RFC 4648 (Base32/Base64Url), FIPS 180-2 (SHA family) — plus roundtrip, tampering, truncation, misuse, async-parity and cancellation checks. It multi-targets `net8.0`, `net10.0` **and** `net48`, so the native code paths are exercised on both modern runtimes and the netstandard2.0/BouncyCastle backend on .NET Framework, on every run (663 test executions in total).

CI/CD (GitHub Actions, [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml)): every push and pull request builds all target frameworks and runs the full test suite on both TFMs; pushes to `main`/`master` that pass additionally pack both NuGet packages and publish them to NuGet.org (requires the `NUGET_API_KEY` repository secret; already-published versions are skipped). The .NET 8 sample remains available as a runnable functional walkthrough.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
