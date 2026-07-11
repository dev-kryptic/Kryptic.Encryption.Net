using System.Security.Cryptography;
using System.Text;

namespace Kryptic.Encryption.Tests;

public class AesGcmCipherTests
{
    private static readonly byte[] Key = DataKeys.GenerateDataKey();
    private const string KeyId = "key_test00000001";

    [Fact]
    public void Encrypt_Decrypt_RoundTrips()
    {
        var plaintext = Encoding.UTF8.GetBytes("postgres://user:hunter2@db.internal:5432/app");

        var envelope = AesGcmCipher.Encrypt(Key, KeyId, plaintext);
        var decrypted = AesGcmCipher.Decrypt(Key, envelope);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_EmptyPlaintext_RoundTrips()
    {
        var envelope = AesGcmCipher.Encrypt(Key, KeyId, []);
        var decrypted = AesGcmCipher.Decrypt(Key, envelope);

        Assert.Empty(decrypted);
    }

    [Fact]
    public void Encrypt_ProducesUniqueNoncesAndCiphertexts()
    {
        var plaintext = Encoding.UTF8.GetBytes("same input");

        var first = AesGcmCipher.Encrypt(Key, KeyId, plaintext);
        var second = AesGcmCipher.Encrypt(Key, KeyId, plaintext);

        Assert.NotEqual(first.Nonce, second.Nonce);
        Assert.NotEqual(first.CiphertextWithTag, second.CiphertextWithTag);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var envelope = AesGcmCipher.Encrypt(Key, KeyId, Encoding.UTF8.GetBytes("value"));
        var wrongKey = DataKeys.GenerateDataKey();

        Assert.ThrowsAny<CryptographicException>(() => AesGcmCipher.Decrypt(wrongKey, envelope));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws()
    {
        var envelope = AesGcmCipher.Encrypt(Key, KeyId, Encoding.UTF8.GetBytes("value"));
        envelope.CiphertextWithTag[0] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => AesGcmCipher.Decrypt(Key, envelope));
    }

    [Fact]
    public void Decrypt_TamperedNonce_Throws()
    {
        var envelope = AesGcmCipher.Encrypt(Key, KeyId, Encoding.UTF8.GetBytes("value"));
        envelope.Nonce[0] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => AesGcmCipher.Decrypt(Key, envelope));
    }

    [Fact]
    public void Decrypt_WithDifferentAssociatedData_Throws()
    {
        var envelope = AesGcmCipher.Encrypt(Key, KeyId, Encoding.UTF8.GetBytes("value"), "context-a"u8.ToArray());

        Assert.ThrowsAny<CryptographicException>(
            () => AesGcmCipher.Decrypt(Key, envelope, "context-b"u8.ToArray()));
    }

    [Fact]
    public void Encrypt_RejectsWrongKeySize()
    {
        Assert.Throws<ArgumentException>(
            () => AesGcmCipher.Encrypt(new byte[16], KeyId, [1, 2, 3]));
    }
}
