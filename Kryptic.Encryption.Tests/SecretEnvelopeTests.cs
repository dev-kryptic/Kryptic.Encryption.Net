using System.Text;

namespace Kryptic.Encryption.Tests;

public class SecretEnvelopeTests
{
    [Fact]
    public void Serialize_Parse_RoundTrips()
    {
        var key = DataKeys.GenerateDataKey();
        var original = AesGcmCipher.Encrypt(key, "key_a1b2c3d4e5f6", Encoding.UTF8.GetBytes("secret"));

        var serialized = original.Serialize();
        var parsed = SecretEnvelope.Parse(serialized);

        Assert.Equal(original.FormatVersion, parsed.FormatVersion);
        Assert.Equal(original.KeyId, parsed.KeyId);
        Assert.Equal(original.Nonce, parsed.Nonce);
        Assert.Equal(original.CiphertextWithTag, parsed.CiphertextWithTag);

        var decrypted = AesGcmCipher.Decrypt(key, parsed);
        Assert.Equal("secret", Encoding.UTF8.GetString(decrypted));
    }

    [Fact]
    public void Serialize_HasExpectedShape()
    {
        var key = DataKeys.GenerateDataKey();
        var envelope = AesGcmCipher.Encrypt(key, "key_abc123", Encoding.UTF8.GetBytes("x"));

        var parts = envelope.Serialize().Split('.');

        Assert.Equal(4, parts.Length);
        Assert.Equal("v1", parts[0]);
        Assert.Equal("key_abc123", parts[1]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("garbage")]
    [InlineData("v1.only.three")]
    [InlineData("v1.a.b.c.d")]                          // too many segments
    [InlineData("v2.key_x.AAAAAAAAAAAAAAAA.AAAA")]      // unknown version
    [InlineData("v1.key with space.AAAAAAAAAAAAAAAA.AAAA")] // invalid key id
    [InlineData("v1.key_x.!!!.AAAA")]                   // invalid base64url nonce
    [InlineData("v1.key_x.AAAA.AAAA")]                  // nonce wrong length
    [InlineData("x1.key_x.AAAAAAAAAAAAAAAA.AAAA")]      // bad version prefix
    public void TryParse_RejectsInvalidInput(string? input)
    {
        var ok = SecretEnvelope.TryParse(input, out var envelope);

        Assert.False(ok);
        Assert.Null(envelope);
    }

    [Fact]
    public void TryParse_RejectsTruncatedCiphertext()
    {
        var key = DataKeys.GenerateDataKey();
        var serialized = AesGcmCipher.Encrypt(key, "key_x", Encoding.UTF8.GetBytes("secret")).Serialize();
        var parts = serialized.Split('.');
        // ciphertext segment shorter than the 16-byte tag
        var truncated = string.Join('.', parts[0], parts[1], parts[2], Base64Url.Encode(new byte[8]));

        Assert.False(SecretEnvelope.TryParse(truncated, out _));
    }

    [Fact]
    public void Parse_InvalidInput_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => SecretEnvelope.Parse("not-an-envelope"));
    }
}
