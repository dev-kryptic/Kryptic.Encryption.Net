# Kryptic Encryption Engine

The open-source (Apache-2.0) cryptography library behind the [Kryptic](https://kryptic.dev)
secrets platform. Every Kryptic component that can see a secret in plaintext is public
and auditable - this package is where all of that cryptography lives.

**No custom primitives.** The engine composes established, widely audited
implementations exclusively:

- **AES-256-GCM** via .NET platform cryptography (`System.Security.Cryptography.AesGcm`)
- **Argon2id** via `Konscious.Security.Cryptography.Argon2`
- **CSPRNG** via `System.Security.Cryptography.RandomNumberGenerator`

Kryptic's engineering lives in the composition - the envelope format, the key hierarchy,
nonce management, context binding, and parameter versioning - never in the primitives.
Read [SECURITY.md](SECURITY.md) for the full security architecture before reading code.

## Install

```
dotnet add package Kryptic.Encryption
```

## What's in the box

| Type | Purpose |
| --- | --- |
| `SecretCipher` | High-level: encrypt/decrypt string secrets to/from the envelope form, bound to a context |
| `SecretEnvelope` | The versioned ciphertext container (`v1.<keyId>.<nonce>.<ciphertext+tag>`) |
| `AesGcmCipher` | AES-256-GCM with random 96-bit nonces and associated-data support |
| `DataKeys` | Data-key generation, key ids, and key wrapping (envelope encryption) |
| `Argon2KeyDerivation` | Argon2id passphrase -> 256-bit key, with versioned parameter sets |
| `PasswordHasher` | Argon2id password hashing (`argon2id.<params>.<salt>.<hash>`) |

## Usage

### Encrypt and decrypt a secret

```csharp
using Kryptic.Encryption;

byte[] dataKey = DataKeys.GenerateDataKey();
string keyId   = DataKeys.GenerateKeyId();

// Context binds the ciphertext to where it belongs - moving it elsewhere fails decryption.
string context = $"secret:{secretId}:env:{environmentId}";

string stored    = SecretCipher.EncryptString(dataKey, keyId, "postgres://…", context);
string plaintext = SecretCipher.DecryptString(dataKey, stored, context);
```

### Envelope encryption (key hierarchy)

```csharp
// The data key is stored only in wrapped form, never in plaintext.
byte[] masterKey = /* held by the platform (Phase 1) or the client (Phase 2) */;

SecretEnvelope wrapped = DataKeys.WrapKey(masterKey, "key_master01", dataKey);
byte[] unwrapped       = DataKeys.UnwrapKey(masterKey, wrapped);
```

### Derive a key from a passphrase

```csharp
byte[] salt = Argon2KeyDerivation.GenerateSalt();
byte[] key  = Argon2KeyDerivation.DeriveKey(passphrase, salt); // Argon2id, 64 MiB, 3 passes
```

### Hash a password

```csharp
string hash = PasswordHasher.Hash(password);
bool ok     = PasswordHasher.Verify(password, hash);
```

## Build & test

```
dotnet build
dotnet test
```

## Reporting vulnerabilities

Please report security issues to **security@kryptic.dev** - see
[SECURITY.md](SECURITY.md) for the disclosure process. Do not open public issues for
vulnerabilities.

## License

[Apache-2.0](LICENSE)
