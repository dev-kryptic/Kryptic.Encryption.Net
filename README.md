# Kryptic.Encryption (.NET)

The C# implementation of Kryptic's open-source (MIT) encryption engine. This is
the package the **Kryptic Platform** consumes: envelope parsing, Argon2id password
hashing, and operational ciphertexts the server itself must read (SSO IdP secrets,
directory sync credentials). Customer secret values are end-to-end encrypted on
clients; this library is not a decrypt path for those values.

**NuGet package id:** `Kryptic.Encryption` (unchanged). This GitHub repository is
named `Kryptic.Encryption.Net` so auditors can tell the three runtimes apart.

Sibling implementations of the same wire formats:

| Repository                                                                      | Runtime | Consumed by |
|---------------------------------------------------------------------------------| --- | --- |
| [Kryptic.Encryption.Net](https://github.com/dev-kryptic/Kryptic.Encryption.Net) | .NET (`Kryptic.Encryption` on nuget.org) | Kryptic Platform |
| [Kryptic.Encryption.NPM](https://github.com/dev-kryptic/Kryptic.Encryption.NPM) | TypeScript / WebCrypto (`@kryptic-dev/encryption`) | Management dashboard |
| [Kryptic.Encryption.Go](https://github.com/dev-kryptic/Kryptic.Encryption.Go)   | Go | Daemon, CLI, Kubernetes operator |

A format change (envelope, sealed box, Argon2id parameters) must land in all three
repositories in the same release. The committed files in `interop-vectors/` are the
contract: every runtime must open and, where the test is deterministic, reproduce
those bytes.

**No custom primitives.** The engine composes established, widely audited
implementations exclusively:

- **AES-256-GCM** via .NET platform cryptography (`System.Security.Cryptography.AesGcm`)
- **Argon2id** via `Konscious.Security.Cryptography.Argon2`
- **CSPRNG** via `System.Security.Cryptography.RandomNumberGenerator`

Kryptic's engineering lives in the composition: the envelope format, the key hierarchy,
nonce management, context binding, and parameter versioning. Never in the primitives.
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
| `SealedBox` | P-256 ECDH sealed box: encrypt a key to a recipient's public key (end-to-end key delivery) |
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

The wrapping key is whoever you pass in. **Kryptic secret values are end-to-end
encrypted:** the org key that opens them exists only on clients (browser, daemon,
CI), delivered via `SealedBox` grants. The platform uses `WrapKey`/`UnwrapKey`
only for operational ciphertexts it must read itself, such as SSO IdP client
secrets, never for your secret values.

```csharp
// The data key is stored only in wrapped form, never in plaintext.
SecretEnvelope wrapped = DataKeys.WrapKey(wrappingKey, "key_x01", dataKey);
byte[] unwrapped       = DataKeys.UnwrapKey(wrappingKey, wrapped);
```

### Seal a key to a recipient (end-to-end delivery)

```csharp
// e.g. an admin's browser granting the org key to an approved daemon device.
KeyPair device = SealedBox.GenerateKeyPair();

SealedKey grant  = SealedBox.Seal(device.PublicKey, "device-key-1", orgKey);
byte[] received  = SealedBox.Open(device, grant); // only the device can do this
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

## Publishing (maintainers)

CI lives in [`.github/workflows/publish.yml`](.github/workflows/publish.yml). Pull
requests only run tests. A publish runs on push to `main`, a `v*.*.*` tag, or
manual `workflow_dispatch`.

### GitHub Actions secrets

Add these on the GitHub repo (`Settings` > `Secrets and variables` > `Actions`):

| Secret | What it is | Where to get it |
| --- | --- | --- |
| `NUGET_USER` | nuget.org username used by [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing) | nuget.org account that owns the `Kryptic.Encryption` package. The `NuGet/login` action exchanges GitHub OIDC for a short-lived API key, so you do **not** store a long-lived `NUGET_API_KEY`. |

Trusted publishing setup on nuget.org (one-time):

1. Sign in as the package owner.
2. Open Trusted Publishing for `Kryptic.Encryption`.
3. Register this GitHub repository (`dev-kryptic/Kryptic.Encryption.Net`), the
   `Build and publish` workflow, and the `main` branch (and tags if you publish from tags).

If the GitHub repo was renamed from `Kryptic.Encryption`, update the trusted-publishing
registration to `dev-kryptic/Kryptic.Encryption.Net` or publishes will fail OIDC.
On GitHub: Settings > General > Repository name.

No other secrets are required. `GITHUB_TOKEN` is issued automatically and is used
only to commit the csproj version bump back to `main`.

### Versioning

Patch versions auto-increment from the latest nuget.org release when major.minor
is unchanged. To ship `1.1.0` or `2.0.0`, set `<Version>` in
`Kryptic.Encryption/Kryptic.Encryption.csproj` (or pass it to `workflow_dispatch`)
and the workflow publishes that version as-is.

## Reporting vulnerabilities

Please report security issues to **security@kryptic.dev**. See
[SECURITY.md](SECURITY.md) for the disclosure process. Do not open public issues for
vulnerabilities.

## License

[MIT](LICENSE)
