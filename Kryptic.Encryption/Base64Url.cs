namespace Kryptic.Encryption;

/// <summary>
/// Base64url (RFC 4648 §5, no padding) — used inside envelopes so the '.' separator
/// can never appear in an encoded segment.
/// </summary>
public static class Base64Url
{
    public static string Encode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static byte[] Decode(string encoded)
    {
        if (!TryDecode(encoded, out var data))
            throw new FormatException("Value is not valid base64url.");
        return data;
    }

    public static bool TryDecode(string? encoded, out byte[] data)
    {
        data = [];
        if (encoded is null || encoded.Length == 0) return false;

        var base64 = encoded.Replace('-', '+').Replace('_', '/');
        base64 = (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            0 => base64,
            _ => string.Empty // length % 4 == 1 is never valid base64
        };
        if (base64.Length == 0) return false;

        var buffer = new byte[base64.Length * 3 / 4];
        if (!Convert.TryFromBase64String(base64, buffer, out var written)) return false;

        data = buffer.AsSpan(0, written).ToArray();
        return true;
    }
}
