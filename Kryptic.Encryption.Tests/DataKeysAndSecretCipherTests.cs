using System.Security.Cryptography;

namespace Kryptic.Encryption.Tests;

public class DataKeysAndSecretCipherTests
{
    [Fact]
    public void WrapKey_UnwrapKey_RoundTrips()
    {
        var masterKey = DataKeys.GenerateDataKey();
        var dataKey = DataKeys.GenerateDataKey();

        var wrapped = DataKeys.WrapKey(masterKey, "key_master000001", dataKey);
        var unwrapped = DataKeys.UnwrapKey(masterKey, wrapped);

        Assert.Equal(dataKey, unwrapped);
        Assert.Equal("key_master000001", wrapped.KeyId);
    }

    [Fact]
    public void UnwrapKey_WithWrongMasterKey_Throws()
    {
        var masterKey = DataKeys.GenerateDataKey();
        var wrapped = DataKeys.WrapKey(masterKey, "key_m", DataKeys.GenerateDataKey());

        Assert.ThrowsAny<CryptographicException>(
            () => DataKeys.UnwrapKey(DataKeys.GenerateDataKey(), wrapped));
    }

    [Fact]
    public void GenerateKeyId_HasExpectedShape()
    {
        var keyId = DataKeys.GenerateKeyId();

        Assert.StartsWith("key_", keyId);
        Assert.Equal("key_".Length + 12, keyId.Length);
    }

    [Fact]
    public void SecretCipher_FullFlow_WithKeyHierarchy()
    {
        // The operational-ciphertext flow end to end:
        // master key -> wrapped org data key -> encrypt a value bound to its context.
        var masterKey = DataKeys.GenerateDataKey();
        var orgDataKey = DataKeys.GenerateDataKey();
        var orgKeyId = DataKeys.GenerateKeyId();
        var wrapped = DataKeys.WrapKey(masterKey, "key_master000001", orgDataKey).Serialize();

        var context = "secret:11111111-1111-1111-1111-111111111111:env:22222222-2222-2222-2222-222222222222";
        var unwrappedKey = DataKeys.UnwrapKey(masterKey, SecretEnvelope.Parse(wrapped));
        var stored = SecretCipher.EncryptString(unwrappedKey, orgKeyId, "postgres://db", context);

        Assert.Equal("postgres://db", SecretCipher.DecryptString(unwrappedKey, stored, context));
    }

    [Fact]
    public void SecretCipher_WrongContext_Throws()
    {
        var key = DataKeys.GenerateDataKey();
        var stored = SecretCipher.EncryptString(key, "key_x", "value", "context-a");

        Assert.ThrowsAny<CryptographicException>(
            () => SecretCipher.DecryptString(key, stored, "context-b"));
    }

    [Fact]
    public void SecretCipher_HandlesUnicodeValues()
    {
        var key = DataKeys.GenerateDataKey();
        const string value = "καλημέρα-κόσμε-🔐-Ω";

        var stored = SecretCipher.EncryptString(key, "key_x", value);

        Assert.Equal(value, SecretCipher.DecryptString(key, stored));
    }
}
