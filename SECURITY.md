# Kryptic Encryption Engine - Security Architecture

This document describes the complete cryptographic design of the Kryptic platform's
encryption engine: what is derived from what, where each key lives, and the exact
boundary of what the Kryptic server can and cannot see. It is written so a security
reviewer can evaluate the architecture before reading a line of code
(Kerckhoffs's principle: the design is public; security depends only on the keys).

## Primitives

The engine composes established implementations only. There are **no custom primitives**.

| Operation | Algorithm | Implementation |
| --- | --- | --- |
| Secret encryption | AES-256-GCM, 96-bit random nonce, 128-bit tag | `System.Security.Cryptography.AesGcm` (.NET platform) |
| Key derivation / password hashing | Argon2id (64 MiB, 3 iterations, parallelism 4 - parameter set v1) | `Konscious.Security.Cryptography.Argon2` |
| Randomness | OS CSPRNG | `System.Security.Cryptography.RandomNumberGenerator` |
| Constant-time comparison | - | `CryptographicOperations.FixedTimeEquals` |

## The envelope format

Every ciphertext the platform stores or transmits is a **secret envelope**:

```
v1.<keyId>.<base64url nonce>.<base64url ciphertext||tag>
```

- `v1` - format version. Layout or parameter changes bump the version; old data keeps
  parsing under its original rules.
- `keyId` - identifies which key produced the ciphertext (`[a-zA-Z0-9_-]`, ≤ 64 chars).
  This is what makes key rotation possible without rewriting history blindly.
- `nonce` - 12 bytes, generated fresh from the CSPRNG for every encryption. The API
  offers no way for a caller to supply a nonce, so nonce reuse by misuse is not possible.
- `ciphertext||tag` - the AES-256-GCM output with the 16-byte authentication tag appended.

The envelope contains no key material and no plaintext; it is safe to store, index, and log.

### Context binding (associated data)

Secret values are encrypted with GCM *associated data* set to a context string:

```
secret:<secretDefinitionId>:env:<environmentId>
```

Decryption fails unless the same context is presented. An attacker with raw database
access therefore cannot swap ciphertexts between rows (e.g. move the production
`DATABASE_URL` ciphertext into a development row a low-privilege user may reveal) -
the authentication tag will not verify.

## Key hierarchy

```
                 ┌─────────────────────────┐
                 │  Master key (32 bytes)   │  Phase 1: platform KMS/config, server memory only
                 │  Phase 2: client-derived  │  Phase 2: never leaves the client
                 └────────────┬────────────┘
                              │ wraps (AES-256-GCM envelope)
                 ┌────────────▼────────────┐
                 │  Org data key (32 bytes) │  stored ONLY in wrapped form, one per organization
                 └────────────┬────────────┘
                              │ encrypts (with context binding)
                 ┌────────────▼────────────┐
                 │  Secret values            │  stored ONLY as envelopes (ciphertext)
                 └─────────────────────────┘
```

- **Data keys** are 32 random bytes from the CSPRNG. They are generated once per
  organization and persisted exclusively in *wrapped* form - an envelope whose plaintext
  happens to be a key.
- **Wrapping** is ordinary AES-256-GCM under the master key, so it inherits the same
  authentication guarantees.
- **Key ids** travel with every ciphertext, allowing data-key rotation: introduce a new
  wrapped key, encrypt new writes under it, re-encrypt old values opportunistically.

### Where each key lives

| Key | At rest | In memory | Ever at the server? |
| --- | --- | --- | --- |
| Master key | Phase 1: platform KMS / deployment secret. Phase 2: nowhere (derived on the client via Argon2id) | Server (Phase 1) / client only (Phase 2) | Phase 1 yes · Phase 2 **no** |
| Org data key | Database, **wrapped only** | Server during operations (Phase 1) / client & daemon (Phase 2) | Phase 1 yes (unwrapped transiently) · Phase 2 wrapped only |
| Secret plaintext | Never | Daemon memory + requesting process | Phase 1 transiently during encrypt/decrypt · Phase 2 **never** |

### Deployment phases

The Kryptic platform adopts this engine in two phases. **The stored data format is
identical in both** - only who holds the master key changes, which is why Phase 2
requires no data migration.

- **Phase 1 (server-side envelope encryption) - current** - the platform holds the
  master key and performs encryption server-side. Protects against database compromise,
  backups, misconfigured storage. Comparable to the default posture of mainstream
  secrets managers. This is what the hosted platform runs today.
- **Phase 2 (end-to-end, blind store) - not shipped** - the master key would be derived
  from client-held authentication material via Argon2id; the daemon and browser clients
  would encrypt and decrypt locally. The server would store and return ciphertext it
  cannot read. This is planned. It is not implemented.

### Key rotation (Phase 1)

Two independent rotations, both enabled by the `keyId` in every envelope:

- **Org data-key rotation** - a fresh data key is generated and every one of the
  organization's ciphertexts (values, version history, IdP client secrets) is
  re-encrypted under it in a single transaction; old keys are deactivated but retained.
  Owner-only, audit-logged.
- **Master-key rotation** - org data keys are *rewrapped* under the new master key; the
  data keys themselves, and therefore all secret ciphertexts, are untouched. Retired
  master keys remain configured for unwrapping until the rewrap pass completes, then
  can be removed.

## Password hashing

Local credentials use Argon2id in the format:

```
argon2id.<parameterSetVersion>.<base64url salt (16 bytes)>.<base64url hash (32 bytes)>
```

- Parameter set v1: 64 MiB memory, 3 iterations, parallelism 4.
- The parameter version is embedded per-hash, so parameters can be raised for new hashes
  while existing ones keep verifying; verification is constant-time.

## What the server can and cannot see

**Phase 1** - the server can transiently see plaintext during encrypt/reveal operations
it performs itself; the database contains only ciphertext envelopes and wrapped keys.

**Phase 2** - the server can see: envelope metadata (version, key id, nonce, ciphertext
length), secret *keys* (names like `DATABASE_URL`), project/environment structure, and
audit metadata. The server can never see: secret values, data keys, or the master key.

In both phases the transport is TLS 1.3, and daemon↔SDK delivery happens over a local
OS socket that never crosses a network.

## Test vectors

Deterministic test coverage lives in `Kryptic.Encryption.Tests` and includes: round-trip,
tamper detection (flipped ciphertext/nonce bytes), wrong-key rejection, wrong-context
rejection, envelope fuzzing (truncation, wrong version, malformed base64), Argon2id
determinism per salt/parameter set, and wrap/unwrap round-trips. AES-256-GCM and Argon2id
correctness against published vectors is delegated to the underlying implementations
(.NET platform crypto is FIPS-validated in supported configurations).

## Reporting a vulnerability

Email **security@kryptic.dev**. We operate a responsible disclosure program and a CVE
coordination process for critical findings. Please do not open public issues for
vulnerabilities.
