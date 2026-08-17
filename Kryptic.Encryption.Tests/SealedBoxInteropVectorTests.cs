using System.Text.Json;

namespace Kryptic.Encryption.Tests;

/// <summary>
/// Locks the sealed-box wire format against the committed interop fixture so the
/// Go and WebCrypto implementations have a byte-exact contract to match. If this
/// test changes, every runtime's output changes - treat it as a format break.
/// </summary>
public class SealedBoxInteropVectorTests
{
    private sealed record Vector(
        string RecipientKeyId,
        string RecipientPrivateKeyHex,
        string RecipientPublicKeyHex,
        string EphemeralPrivateKeyHex,
        string EphemeralPublicKeyHex,
        string PlaintextHex,
        string Sealed);

    private static Vector Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Vectors", "sealed-box-p256.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        return new Vector(
            root.GetProperty("recipientKeyId").GetString()!,
            root.GetProperty("recipientPrivateKeyHex").GetString()!,
            root.GetProperty("recipientPublicKeyHex").GetString()!,
            root.GetProperty("ephemeralPrivateKeyHex").GetString()!,
            root.GetProperty("ephemeralPublicKeyHex").GetString()!,
            root.GetProperty("plaintextHex").GetString()!,
            root.GetProperty("sealed").GetString()!);
    }

    [Fact]
    public void Open_ProducesExpectedPlaintext()
    {
        var vector = Load();
        var recipient = new KeyPair(
            Convert.FromHexString(vector.RecipientPublicKeyHex),
            Convert.FromHexString(vector.RecipientPrivateKeyHex));

        var opened = SealedBox.Open(recipient, SealedKey.Parse(vector.Sealed));

        Assert.Equal(vector.PlaintextHex, Convert.ToHexStringLower(opened));
    }

    [Fact]
    public void SealWithFixedEphemeral_ReproducesFixtureByteForByte()
    {
        var vector = Load();
        var ephemeral = new KeyPair(
            Convert.FromHexString(vector.EphemeralPublicKeyHex),
            Convert.FromHexString(vector.EphemeralPrivateKeyHex));
        var recipientPublicKey = Convert.FromHexString(vector.RecipientPublicKeyHex);
        var plaintext = Convert.FromHexString(vector.PlaintextHex);

        var box = SealedBox.SealWithEphemeralForTests(ephemeral, recipientPublicKey, vector.RecipientKeyId, plaintext);

        Assert.Equal(vector.Sealed, box.Serialize());
    }
}
