using System.Security.Cryptography;
using System.Text;

namespace Kryptic.Encryption.Tests;

public class SealedBoxTests
{
    private const string RecipientKeyId = "ukey_test000001";

    [Fact]
    public void Seal_Open_RoundTrips()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var plaintext = DataKeys.GenerateDataKey();

        var box = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, plaintext);
        var opened = SealedBox.Open(recipient, box);

        Assert.Equal(plaintext, opened);
    }

    [Fact]
    public void Seal_Open_RoundTrips_ThroughSerialization()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var plaintext = Encoding.UTF8.GetBytes("the org data key would go here");

        var serialized = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, plaintext).Serialize();
        var parsed = SealedKey.Parse(serialized);
        var opened = SealedBox.Open(recipient, parsed);

        Assert.Equal(plaintext, opened);
    }

    [Fact]
    public void Seal_ProducesUniqueEphemeralKeysAndCiphertexts()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var plaintext = Encoding.UTF8.GetBytes("same input");

        var first = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, plaintext);
        var second = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, plaintext);

        Assert.NotEqual(first.EphemeralPublicKey, second.EphemeralPublicKey);
        Assert.NotEqual(first.CiphertextWithTag, second.CiphertextWithTag);
    }

    [Fact]
    public void Open_WithWrongRecipient_Throws()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var attacker = SealedBox.GenerateKeyPair();
        var box = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, DataKeys.GenerateDataKey());

        Assert.ThrowsAny<CryptographicException>(() => SealedBox.Open(attacker, box));
    }

    [Fact]
    public void Open_TamperedCiphertext_Throws()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var box = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, DataKeys.GenerateDataKey());
        box.CiphertextWithTag[0] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => SealedBox.Open(recipient, box));
    }

    [Fact]
    public void Open_TamperedEphemeralKey_Throws()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var box = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, DataKeys.GenerateDataKey());
        // Flip a byte in the ephemeral point's X coordinate (still a validly-shaped point).
        box.EphemeralPublicKey[1] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => SealedBox.Open(recipient, box));
    }

    [Fact]
    public void Seal_RejectsMalformedPublicKey()
    {
        Assert.Throws<ArgumentException>(
            () => SealedBox.Seal(new byte[65], RecipientKeyId, [1, 2, 3]));
    }

    [Fact]
    public void GenerateKeyPair_ProducesValidlySizedKeys()
    {
        var keyPair = SealedBox.GenerateKeyPair();

        Assert.Equal(SealedKey.PublicKeySizeBytes, keyPair.PublicKey.Length);
        Assert.Equal(0x04, keyPair.PublicKey[0]);
        Assert.Equal(32, keyPair.PrivateKey.Length);
    }

    [Fact]
    public void SealedKey_Serialize_Parse_RoundTrips()
    {
        var recipient = SealedBox.GenerateKeyPair();
        var box = SealedBox.Seal(recipient.PublicKey, RecipientKeyId, DataKeys.GenerateDataKey());

        var parsed = SealedKey.Parse(box.Serialize());

        Assert.Equal(box.FormatVersion, parsed.FormatVersion);
        Assert.Equal(box.RecipientKeyId, parsed.RecipientKeyId);
        Assert.Equal(box.EphemeralPublicKey, parsed.EphemeralPublicKey);
        Assert.Equal(box.Nonce, parsed.Nonce);
        Assert.Equal(box.CiphertextWithTag, parsed.CiphertextWithTag);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-sealed-box")]
    [InlineData("sbx.v2.key.AA.BB.CC")]
    [InlineData("env.v1.key.AA.BB.CC")]
    public void SealedKey_TryParse_RejectsInvalid(string value)
    {
        Assert.False(SealedKey.TryParse(value, out _));
    }
}
