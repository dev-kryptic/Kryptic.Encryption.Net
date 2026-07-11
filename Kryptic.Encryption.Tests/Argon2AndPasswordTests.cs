namespace Kryptic.Encryption.Tests;

public class Argon2AndPasswordTests
{
    [Fact]
    public void DeriveKey_IsDeterministicForSameInputs()
    {
        var salt = Argon2KeyDerivation.GenerateSalt();

        var first = Argon2KeyDerivation.DeriveKey("correct horse battery staple", salt);
        var second = Argon2KeyDerivation.DeriveKey("correct horse battery staple", salt);

        Assert.Equal(first, second);
        Assert.Equal(Argon2KeyDerivation.DerivedKeySizeBytes, first.Length);
    }

    [Fact]
    public void DeriveKey_DifferentSalt_DifferentKey()
    {
        var saltA = Argon2KeyDerivation.GenerateSalt();
        var saltB = Argon2KeyDerivation.GenerateSalt();

        var keyA = Argon2KeyDerivation.DeriveKey("passphrase", saltA);
        var keyB = Argon2KeyDerivation.DeriveKey("passphrase", saltB);

        Assert.NotEqual(keyA, keyB);
    }

    [Fact]
    public void DeriveKey_DifferentPassphrase_DifferentKey()
    {
        var salt = Argon2KeyDerivation.GenerateSalt();

        var keyA = Argon2KeyDerivation.DeriveKey("passphrase-a", salt);
        var keyB = Argon2KeyDerivation.DeriveKey("passphrase-b", salt);

        Assert.NotEqual(keyA, keyB);
    }

    [Fact]
    public void DeriveKey_RejectsWrongSaltSize()
    {
        Assert.Throws<ArgumentException>(
            () => Argon2KeyDerivation.DeriveKey("passphrase", new byte[8]));
    }

    [Fact]
    public void PasswordHasher_Hash_Verify_RoundTrips()
    {
        var hash = PasswordHasher.Hash("s3cure-Passw0rd!");

        Assert.StartsWith("argon2id.1.", hash);
        Assert.True(PasswordHasher.Verify("s3cure-Passw0rd!", hash));
        Assert.False(PasswordHasher.Verify("wrong-password", hash));
    }

    [Fact]
    public void PasswordHasher_ProducesUniqueSalts()
    {
        var first = PasswordHasher.Hash("same-password");
        var second = PasswordHasher.Hash("same-password");

        Assert.NotEqual(first, second);
        Assert.True(PasswordHasher.Verify("same-password", first));
        Assert.True(PasswordHasher.Verify("same-password", second));
    }

    [Theory]
    [InlineData("")]
    [InlineData("nonsense")]
    [InlineData("argon2id.999.AAAAAAAAAAAAAAAAAAAAAA.AAAA")] // unknown parameter version
    [InlineData("bcrypt.1.AAAAAAAAAAAAAAAAAAAAAA.AAAA")]     // wrong algorithm prefix
    public void PasswordHasher_Verify_RejectsMalformedHashes(string storedHash)
    {
        Assert.False(PasswordHasher.Verify("password", storedHash));
    }
}
