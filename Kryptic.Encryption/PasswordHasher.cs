using System.Security.Cryptography;

namespace Kryptic.Encryption;

/// <summary>
/// Argon2id password hashing for Kryptic local credentials.
///
/// Stored form: <c>argon2id.&lt;paramsVersion&gt;.&lt;base64url salt&gt;.&lt;base64url hash&gt;</c>
/// The parameter-set version is embedded so parameters can be raised without breaking
/// existing hashes; verification always uses the parameters the hash was created with.
/// </summary>
public static class PasswordHasher
{
    private const string Prefix = "argon2id";

    public static string Hash(string password)
    {
        var parameters = Argon2Parameters.V1;
        var salt = Argon2KeyDerivation.GenerateSalt();
        var hash = Argon2KeyDerivation.DeriveKey(password, salt, parameters);

        var parts = new List<string>
        {
            Prefix,
            parameters.Version.ToString(),
            Base64Url.Encode(salt),
            Base64Url.Encode(hash)
        };
        return string.Join('.', parts);
    }

    public static bool Verify(string password, string storedHash)
    {
        var parts = storedHash.Split('.');
        if (parts.Length != 4 || parts[0] != Prefix) return false;
        if (!int.TryParse(parts[1], out var parametersVersion)) return false;
        if (!Base64Url.TryDecode(parts[2], out var salt)) return false;
        if (!Base64Url.TryDecode(parts[3], out var expectedHash)) return false;

        Argon2Parameters parameters;
        try
        {
            parameters = Argon2Parameters.ForVersion(parametersVersion);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length != Argon2KeyDerivation.SaltSizeBytes) return false;

        var actualHash = Argon2KeyDerivation.DeriveKey(password, salt, parameters);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}
