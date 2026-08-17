namespace Kryptic.Encryption;

/// <summary>
/// The versioned container every Kryptic ciphertext is stored and transmitted in.
///
/// Serialized form: <c>v1.&lt;keyId&gt;.&lt;nonce&gt;.&lt;ciphertext+tag&gt;</c>
/// where nonce and ciphertext are base64url (no padding) and keyId identifies which
/// key encrypted the value, so keys can be rotated without re-encrypting history blindly.
///
/// The envelope carries no plaintext and no key material - it is safe to store and log.
/// </summary>
public sealed class SecretEnvelope
{
    public const int CurrentFormatVersion = 1;

    /// <summary>Format version, so parameters and layout can evolve without breaking stored data.</summary>
    public int FormatVersion { get; }

    /// <summary>Identifier of the key that produced this ciphertext (e.g. "key_a1b2c3d4e5f6").</summary>
    public string KeyId { get; }

    /// <summary>96-bit nonce, unique per encryption, generated randomly. Never reused for the same key.</summary>
    public byte[] Nonce { get; }

    /// <summary>The AES-256-GCM ciphertext with the 128-bit authentication tag appended.</summary>
    public byte[] CiphertextWithTag { get; }

    public SecretEnvelope(int formatVersion, string keyId, byte[] nonce, byte[] ciphertextWithTag)
    {
        if (formatVersion != CurrentFormatVersion)
            throw new FormatException($"Unsupported envelope format version '{formatVersion}'.");
        if (string.IsNullOrEmpty(keyId) || !IsValidKeyId(keyId))
            throw new FormatException("Envelope key id must be non-empty and contain only [a-zA-Z0-9_-].");
        if (nonce.Length != AesGcmCipher.NonceSizeBytes)
            throw new FormatException($"Envelope nonce must be {AesGcmCipher.NonceSizeBytes} bytes.");
        if (ciphertextWithTag.Length < AesGcmCipher.TagSizeBytes)
            throw new FormatException("Envelope ciphertext is shorter than the authentication tag.");

        FormatVersion = formatVersion;
        KeyId = keyId;
        Nonce = nonce;
        CiphertextWithTag = ciphertextWithTag;
    }

    /// <summary>Serializes to the canonical string form used for storage and transport.</summary>
    public string Serialize()
    {
        var parts = new List<string>
        {
            $"v{FormatVersion}",
            KeyId,
            Base64Url.Encode(Nonce),
            Base64Url.Encode(CiphertextWithTag)
        };
        return string.Join('.', parts);
    }

    public static SecretEnvelope Parse(string value)
    {
        if (!TryParse(value, out var envelope) || envelope is null)
            throw new FormatException("Value is not a valid Kryptic secret envelope.");
        return envelope;
    }

    public static bool TryParse(string? value, out SecretEnvelope? envelope)
    {
        envelope = null;
        if (string.IsNullOrWhiteSpace(value)) return false;

        var parts = value.Split('.');
        if (parts.Length != 4) return false;

        if (parts[0].Length < 2 || parts[0][0] != 'v') return false;
        if (!int.TryParse(parts[0].AsSpan(1), out var version)) return false;
        if (version != CurrentFormatVersion) return false;

        if (!IsValidKeyId(parts[1])) return false;
        if (!Base64Url.TryDecode(parts[2], out var nonce)) return false;
        if (!Base64Url.TryDecode(parts[3], out var ciphertext)) return false;
        if (nonce.Length != AesGcmCipher.NonceSizeBytes) return false;
        if (ciphertext.Length < AesGcmCipher.TagSizeBytes) return false;

        envelope = new SecretEnvelope(version, parts[1], nonce, ciphertext);
        return true;
    }

    private static bool IsValidKeyId(string keyId)
    {
        return keyId.Length is > 0 and <= 64 &&
               keyId.All(IsValidKeyIdCharacter);
    }

    private static bool IsValidKeyIdCharacter(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '_' or '-';
}
