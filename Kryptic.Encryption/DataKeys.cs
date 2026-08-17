using System.Security.Cryptography;

namespace Kryptic.Encryption;

/// <summary>
/// Data-key generation and key wrapping - the envelope-encryption building blocks.
///
/// A data key encrypts actual secret values. The data key itself is stored only in
/// wrapped (encrypted) form, wrapped by a higher-level key. Kryptic currently uses a
/// platform master key (Phase 1). A client-held wrapping key (Phase 2) is planned and
/// is not shipped. See SECURITY.md for the full key hierarchy.
/// </summary>
public static class DataKeys
{
    /// <summary>Generates a fresh 256-bit data key from the OS CSPRNG.</summary>
    public static byte[] GenerateDataKey()
    {
        return RandomNumberGenerator.GetBytes(AesGcmCipher.KeySizeBytes);
    }

    /// <summary>Generates a key identifier such as "key_a1b2c3d4e5f6" (12 hex chars, 48 bits).</summary>
    public static string GenerateKeyId()
    {
        var bytes = RandomNumberGenerator.GetBytes(6);
        return "key_" + Convert.ToHexStringLower(bytes);
    }

    /// <summary>
    /// Wraps (encrypts) a data key under a wrapping key. The result is a normal envelope
    /// whose plaintext happens to be a key - safe to store next to the data it protects.
    /// </summary>
    public static SecretEnvelope WrapKey(byte[] wrappingKey, string wrappingKeyId, byte[] dataKey)
    {
        if (dataKey.Length != AesGcmCipher.KeySizeBytes)
            throw new ArgumentException($"Data key must be {AesGcmCipher.KeySizeBytes} bytes.", nameof(dataKey));

        return AesGcmCipher.Encrypt(wrappingKey, wrappingKeyId, dataKey);
    }

    /// <summary>Unwraps (decrypts) a wrapped data key.</summary>
    public static byte[] UnwrapKey(byte[] wrappingKey, SecretEnvelope wrappedKey)
    {
        var dataKey = AesGcmCipher.Decrypt(wrappingKey, wrappedKey);
        if (dataKey.Length != AesGcmCipher.KeySizeBytes)
            throw new CryptographicException("Unwrapped value is not a valid data key.");
        return dataKey;
    }
}
