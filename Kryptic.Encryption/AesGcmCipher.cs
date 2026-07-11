using System.Security.Cryptography;

namespace Kryptic.Encryption;

/// <summary>
/// AES-256-GCM authenticated encryption. Thin composition over the platform's
/// <see cref="AesGcm"/> — no custom primitives (see SECURITY.md).
///
/// Associated data binds a ciphertext to its context (e.g. secret id + environment id)
/// so an attacker with database access cannot swap ciphertexts between rows undetected.
/// </summary>
public static class AesGcmCipher
{
    public const int KeySizeBytes = 32;   // AES-256
    public const int NonceSizeBytes = 12; // 96-bit, the GCM-recommended size
    public const int TagSizeBytes = 16;   // 128-bit authentication tag

    /// <summary>
    /// Encrypts plaintext under the given key. A fresh random nonce is generated per call —
    /// callers must never supply or reuse nonces.
    /// </summary>
    public static SecretEnvelope Encrypt(byte[] key, string keyId, byte[] plaintext, byte[]? associatedData = null)
    {
        ValidateKey(key);

        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var ciphertextWithTag = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(ciphertextWithTag, 0);
        tag.CopyTo(ciphertextWithTag, ciphertext.Length);

        return new SecretEnvelope(SecretEnvelope.CurrentFormatVersion, keyId, nonce, ciphertextWithTag);
    }

    /// <summary>
    /// Decrypts an envelope. Throws <see cref="CryptographicException"/> when the key is wrong,
    /// the ciphertext was tampered with, or the associated data does not match.
    /// </summary>
    public static byte[] Decrypt(byte[] key, SecretEnvelope envelope, byte[]? associatedData = null)
    {
        ValidateKey(key);

        var ciphertextLength = envelope.CiphertextWithTag.Length - TagSizeBytes;
        var ciphertext = envelope.CiphertextWithTag.AsSpan(0, ciphertextLength);
        var tag = envelope.CiphertextWithTag.AsSpan(ciphertextLength, TagSizeBytes);
        var plaintext = new byte[ciphertextLength];

        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Decrypt(envelope.Nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }

    private static void ValidateKey(byte[] key)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"Key must be {KeySizeBytes} bytes (AES-256).", nameof(key));
    }
}
