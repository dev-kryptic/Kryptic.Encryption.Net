namespace Kryptic.Encryption;

/// <summary>
/// The versioned container for a value sealed to a recipient's public key
/// (P-256 ECDH sealed box). This is how the org data key is wrapped to each
/// recipient (user, daemon, machine, recovery) in the blind store.
///
/// Serialized form:
/// <c>sbx.v1.&lt;recipientKeyId&gt;.&lt;ephemeralPub&gt;.&lt;nonce&gt;.&lt;ciphertext+tag&gt;</c>
/// where ephemeralPub, nonce and ciphertext+tag are base64url (no padding).
///
/// The sealed box carries no private key material and is safe to store and log.
/// </summary>
public sealed class SealedKey
{
    public const int CurrentFormatVersion = 1;

    /// <summary>Uncompressed SEC1 P-256 public point length: 0x04 || X(32) || Y(32).</summary>
    public const int PublicKeySizeBytes = 65;

    /// <summary>Format version, so the layout can evolve without breaking stored data.</summary>
    public int FormatVersion { get; }

    /// <summary>Identifier of the recipient public key this value was sealed to.</summary>
    public string RecipientKeyId { get; }

    /// <summary>The sender's ephemeral P-256 public key (uncompressed SEC1, 65 bytes).</summary>
    public byte[] EphemeralPublicKey { get; }

    /// <summary>96-bit AES-GCM nonce.</summary>
    public byte[] Nonce { get; }

    /// <summary>AES-256-GCM ciphertext with the 128-bit authentication tag appended.</summary>
    public byte[] CiphertextWithTag { get; }

    public SealedKey(int formatVersion, string recipientKeyId, byte[] ephemeralPublicKey, byte[] nonce, byte[] ciphertextWithTag)
    {
        if (formatVersion != CurrentFormatVersion)
            throw new FormatException($"Unsupported sealed-box format version '{formatVersion}'.");
        if (string.IsNullOrEmpty(recipientKeyId) || !IsValidKeyId(recipientKeyId))
            throw new FormatException("Sealed-box recipient key id must be non-empty and contain only [a-zA-Z0-9_-].");
        if (ephemeralPublicKey.Length != PublicKeySizeBytes || ephemeralPublicKey[0] != 0x04)
            throw new FormatException($"Ephemeral public key must be a {PublicKeySizeBytes}-byte uncompressed SEC1 point.");
        if (nonce.Length != AesGcmCipher.NonceSizeBytes)
            throw new FormatException($"Sealed-box nonce must be {AesGcmCipher.NonceSizeBytes} bytes.");
        if (ciphertextWithTag.Length < AesGcmCipher.TagSizeBytes)
            throw new FormatException("Sealed-box ciphertext is shorter than the authentication tag.");

        FormatVersion = formatVersion;
        RecipientKeyId = recipientKeyId;
        EphemeralPublicKey = ephemeralPublicKey;
        Nonce = nonce;
        CiphertextWithTag = ciphertextWithTag;
    }

    /// <summary>Serializes to the canonical string form used for storage and transport.</summary>
    public string Serialize()
    {
        var parts = new List<string>
        {
            $"sbx.v{FormatVersion}",
            RecipientKeyId,
            Base64Url.Encode(EphemeralPublicKey),
            Base64Url.Encode(Nonce),
            Base64Url.Encode(CiphertextWithTag)
        };
        return string.Join('.', parts);
    }

    public static SealedKey Parse(string value)
    {
        if (!TryParse(value, out var sealedKey) || sealedKey is null)
            throw new FormatException("Value is not a valid Kryptic sealed box.");
        return sealedKey;
    }

    public static bool TryParse(string? value, out SealedKey? sealedKey)
    {
        sealedKey = null;
        if (string.IsNullOrWhiteSpace(value)) return false;

        // "sbx.v1" contains a '.', so the prefix spans the first two dot-separated
        // segments; the remaining three are recipientKeyId, ephemeralPub, nonce, ct.
        var parts = value.Split('.');
        if (parts.Length != 6) return false;

        if (parts[0] != "sbx") return false;
        if (parts[1].Length < 2 || parts[1][0] != 'v') return false;
        if (!int.TryParse(parts[1].AsSpan(1), out var version)) return false;
        if (version != CurrentFormatVersion) return false;

        if (!IsValidKeyId(parts[2])) return false;
        if (!Base64Url.TryDecode(parts[3], out var ephemeralPub)) return false;
        if (!Base64Url.TryDecode(parts[4], out var nonce)) return false;
        if (!Base64Url.TryDecode(parts[5], out var ciphertext)) return false;

        if (ephemeralPub.Length != PublicKeySizeBytes || ephemeralPub[0] != 0x04) return false;
        if (nonce.Length != AesGcmCipher.NonceSizeBytes) return false;
        if (ciphertext.Length < AesGcmCipher.TagSizeBytes) return false;

        sealedKey = new SealedKey(version, parts[2], ephemeralPub, nonce, ciphertext);
        return true;
    }

    private static bool IsValidKeyId(string keyId)
    {
        return keyId.Length is > 0 and <= 64 && keyId.All(IsValidKeyIdCharacter);
    }

    private static bool IsValidKeyIdCharacter(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '_' or '-';
}
