using System.Text;

namespace Kryptic.Encryption;

/// <summary>
/// The high-level entry point most callers want: encrypt/decrypt string secrets to and
/// from the serialized envelope form, optionally bound to a context string.
///
/// The context (e.g. "secret:{secretDefinitionId}:env:{environmentId}") becomes GCM
/// associated data - decryption fails if a ciphertext is moved to a different context,
/// which defeats ciphertext-swapping attacks by anyone with raw storage access.
/// </summary>
public static class SecretCipher
{
    public static string EncryptString(byte[] key, string keyId, string plaintext, string? context = null)
    {
        var envelope = AesGcmCipher.Encrypt(
            key,
            keyId,
            Encoding.UTF8.GetBytes(plaintext),
            ContextToAssociatedData(context));

        return envelope.Serialize();
    }

    public static string DecryptString(byte[] key, string serializedEnvelope, string? context = null)
    {
        var envelope = SecretEnvelope.Parse(serializedEnvelope);
        var plaintext = AesGcmCipher.Decrypt(key, envelope, ContextToAssociatedData(context));
        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[]? ContextToAssociatedData(string? context)
    {
        return context is null ? null : Encoding.UTF8.GetBytes(context);
    }
}
