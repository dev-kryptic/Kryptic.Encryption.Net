using System.Text.Json;

namespace Kryptic.Encryption.Tests;

/// <summary>
/// Locks the Argon2id V1 parameter set against the committed interop fixture so
/// the browser (WASM) implementation has a known answer to match.
/// </summary>
public class Argon2InteropVectorTests
{
    [Fact]
    public void DeriveKey_MatchesFixture()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Vectors", "argon2id.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;

        var passphrase = root.GetProperty("passphrase").GetString()!;
        var salt = Convert.FromHexString(root.GetProperty("saltHex").GetString()!);
        var expected = root.GetProperty("derivedKeyHex").GetString()!;
        var parameters = Argon2Parameters.ForVersion(root.GetProperty("parameterSetVersion").GetInt32());

        var derived = Argon2KeyDerivation.DeriveKey(passphrase, salt, parameters);

        Assert.Equal(expected, Convert.ToHexStringLower(derived));
    }
}
