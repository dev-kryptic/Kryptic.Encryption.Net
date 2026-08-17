using System.Security.Cryptography;
using System.Text;

namespace Kryptic.Encryption;

/// <summary>
/// A P-256 ECDH sealed box: encrypt a value to a recipient's public key so that
/// only the holder of the matching private key can open it. This is the
/// asymmetric wrapping layer the blind store uses to distribute the org
/// key to each recipient (user, daemon, machine, recovery key).
///
/// Construction (ECIES): the sender generates a fresh ephemeral P-256 key pair,
/// performs ECDH against the recipient public key, derives a 256-bit AES key with
/// HKDF-SHA256, and encrypts with AES-256-GCM. Only the raw x-coordinate of the
/// ECDH agreement is used as HKDF input keying material, which is what WebCrypto
/// (deriveBits) and Go (crypto/ecdh) also produce - so the three runtimes interop.
///
/// No custom primitives: ECDH, HKDF and AES-GCM are all platform implementations.
/// </summary>
public static class SealedBox
{
    /// <summary>HKDF info label, bound together with both public keys (see DeriveKey).</summary>
    private static readonly byte[] HkdfLabel = "kryptic-sealed-box-v1"u8.ToArray();

    private const int SharedSecretSizeBytes = 32; // P-256 field element (x-coordinate)

    /// <summary>Generates a fresh P-256 key pair for a recipient (user, daemon, machine).</summary>
    public static KeyPair GenerateKeyPair()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdh.ExportParameters(includePrivateParameters: true);
        return new KeyPair(EncodePublicKey(parameters), LeftPad(parameters.D!, 32));
    }

    /// <summary>
    /// Seals <paramref name="plaintext"/> to <paramref name="recipientPublicKey"/>. A fresh
    /// ephemeral key pair is generated per call - the result can only be opened with the
    /// recipient's private key.
    /// </summary>
    public static SealedKey Seal(byte[] recipientPublicKey, string recipientKeyId, byte[] plaintext)
    {
        ValidatePublicKey(recipientPublicKey, nameof(recipientPublicKey));

        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephemeralPublicKey = EncodePublicKey(ephemeral.ExportParameters(false));

        return SealWithEphemeral(ephemeral, ephemeralPublicKey, recipientPublicKey, recipientKeyId, plaintext);
    }

    /// <summary>Opens a sealed box with the recipient key pair, returning the plaintext.</summary>
    public static byte[] Open(KeyPair recipient, SealedKey box)
    {
        ValidatePublicKey(recipient.PublicKey, nameof(recipient));

        using var recipientEcdh = ImportKeyPair(recipient);
        using var ephemeralPublic = ImportPublicKey(box.EphemeralPublicKey);

        var sharedSecret = recipientEcdh.DeriveRawSecretAgreement(ephemeralPublic.PublicKey);
        var (aesKey, _) = DeriveKeyAndNonce(sharedSecret, box.EphemeralPublicKey, recipient.PublicKey);

        var envelope = new SecretEnvelope(
            SecretEnvelope.CurrentFormatVersion, box.RecipientKeyId, box.Nonce, box.CiphertextWithTag);
        try
        {
            return AesGcmCipher.Decrypt(aesKey, envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    // Internal seam so tests can produce deterministic known-answer vectors by
    // supplying a fixed ephemeral key. Production callers use Seal (random ephemeral).
    internal static SealedKey SealWithEphemeralForTests(KeyPair ephemeralKeyPair, byte[] recipientPublicKey, string recipientKeyId, byte[] plaintext)
    {
        ValidatePublicKey(recipientPublicKey, nameof(recipientPublicKey));
        using var ephemeral = ImportKeyPair(ephemeralKeyPair);
        return SealWithEphemeral(ephemeral, ephemeralKeyPair.PublicKey, recipientPublicKey, recipientKeyId, plaintext);
    }

    private static SealedKey SealWithEphemeral(ECDiffieHellman ephemeral, byte[] ephemeralPublicKey, byte[] recipientPublicKey, string recipientKeyId, byte[] plaintext)
    {
        using var recipient = ImportPublicKey(recipientPublicKey);

        var sharedSecret = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);
        var (aesKey, nonce) = DeriveKeyAndNonce(sharedSecret, ephemeralPublicKey, recipientPublicKey);
        try
        {
            var envelope = AesGcmCipher.EncryptWithNonce(aesKey, recipientKeyId, plaintext, nonce);
            return new SealedKey(
                SealedKey.CurrentFormatVersion, recipientKeyId, ephemeralPublicKey, envelope.Nonce, envelope.CiphertextWithTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    /// <summary>
    /// HKDF-SHA256 over the ECDH shared secret, expanded into a 256-bit AES key and a
    /// 96-bit nonce. The derivation is bound to both the ephemeral and recipient public
    /// keys so a shared secret can never be reused under a different pairing. The nonce is
    /// derived rather than random: the per-message key (from the ephemeral agreement) is
    /// never reused, so a deterministic nonce is safe and makes sealing reproducible.
    /// </summary>
    private static (byte[] Key, byte[] Nonce) DeriveKeyAndNonce(byte[] sharedSecret, byte[] ephemeralPublicKey, byte[] recipientPublicKey)
    {
        var info = new byte[HkdfLabel.Length + ephemeralPublicKey.Length + recipientPublicKey.Length];
        var offset = 0;
        HkdfLabel.CopyTo(info, offset); offset += HkdfLabel.Length;
        ephemeralPublicKey.CopyTo(info, offset); offset += ephemeralPublicKey.Length;
        recipientPublicKey.CopyTo(info, offset);

        var okm = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: sharedSecret,
            outputLength: AesGcmCipher.KeySizeBytes + AesGcmCipher.NonceSizeBytes,
            salt: null,
            info: info);

        var key = okm[..AesGcmCipher.KeySizeBytes];
        var nonce = okm[AesGcmCipher.KeySizeBytes..];
        return (key, nonce);
    }

    private static ECDiffieHellman ImportPublicKey(byte[] publicKey)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = publicKey[1..33],
                Y = publicKey[33..65]
            }
        };
        return ECDiffieHellman.Create(parameters);
    }

    private static ECDiffieHellman ImportKeyPair(KeyPair keyPair)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = keyPair.PublicKey[1..33],
                Y = keyPair.PublicKey[33..65]
            },
            D = keyPair.PrivateKey
        };
        return ECDiffieHellman.Create(parameters);
    }

    private static byte[] EncodePublicKey(ECParameters parameters)
    {
        var publicKey = new byte[SealedKey.PublicKeySizeBytes];
        publicKey[0] = 0x04;
        LeftPad(parameters.Q.X!, 32).CopyTo(publicKey, 1);
        LeftPad(parameters.Q.Y!, 32).CopyTo(publicKey, 33);
        return publicKey;
    }

    private static byte[] LeftPad(byte[] value, int length)
    {
        if (value.Length == length) return value;
        if (value.Length > length)
            throw new CryptographicException($"Field element longer than {length} bytes.");
        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    private static void ValidatePublicKey(byte[] publicKey, string paramName)
    {
        if (publicKey.Length != SealedKey.PublicKeySizeBytes || publicKey[0] != 0x04)
            throw new ArgumentException(
                $"Public key must be a {SealedKey.PublicKeySizeBytes}-byte uncompressed SEC1 P-256 point.", paramName);
    }
}

/// <summary>
/// A P-256 key pair. The public key is the 65-byte uncompressed SEC1 point; the
/// private key is the 32-byte big-endian scalar. Both encodings are the portable
/// forms understood by WebCrypto and Go, so key material generated in one runtime
/// can be used in another.
/// </summary>
public sealed class KeyPair
{
    public byte[] PublicKey { get; }
    public byte[] PrivateKey { get; }

    public KeyPair(byte[] publicKey, byte[] privateKey)
    {
        if (publicKey.Length != SealedKey.PublicKeySizeBytes || publicKey[0] != 0x04)
            throw new ArgumentException(
                $"Public key must be a {SealedKey.PublicKeySizeBytes}-byte uncompressed SEC1 P-256 point.", nameof(publicKey));
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be a 32-byte P-256 scalar.", nameof(privateKey));

        PublicKey = publicKey;
        PrivateKey = privateKey;
    }
}
