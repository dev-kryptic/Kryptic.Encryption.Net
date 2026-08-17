using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Kryptic.Encryption;

/// <summary>
/// The Argon2id parameter set used for a derivation. Parameter sets are versioned so
/// they can be raised over time - the version travels with every derived value, and old
/// values keep verifying with the parameters they were created under.
/// </summary>
public sealed class Argon2Parameters
{
    public int Version { get; init; }
    public int MemoryKibibytes { get; init; }
    public int Iterations { get; init; }
    public int Parallelism { get; init; }

    /// <summary>Parameter set 1 - 64 MiB, 3 passes, 4 lanes (OWASP-recommended territory).</summary>
    public static readonly Argon2Parameters V1 = new()
    {
        Version = 1,
        MemoryKibibytes = 64 * 1024,
        Iterations = 3,
        Parallelism = 4
    };

    public static Argon2Parameters ForVersion(int version)
    {
        return version switch
        {
            1 => V1,
            _ => throw new FormatException($"Unknown Argon2 parameter set version '{version}'.")
        };
    }
}

/// <summary>
/// Argon2id key derivation - turns a low-entropy passphrase into a 256-bit key.
/// Used for deriving user keys from authentication material and for password hashing.
/// Composition only: the Argon2id implementation is Konscious.Security.Cryptography.
/// </summary>
public static class Argon2KeyDerivation
{
    public const int SaltSizeBytes = 16;
    public const int DerivedKeySizeBytes = 32;

    public static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(SaltSizeBytes);
    }

    public static byte[] DeriveKey(string passphrase, byte[] salt, Argon2Parameters? parameters = null)
    {
        if (salt.Length != SaltSizeBytes)
            throw new ArgumentException($"Salt must be {SaltSizeBytes} bytes.", nameof(salt));

        var p = parameters ?? Argon2Parameters.V1;

        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(passphrase))
        {
            Salt = salt,
            MemorySize = p.MemoryKibibytes,
            Iterations = p.Iterations,
            DegreeOfParallelism = p.Parallelism
        };

        return argon2.GetBytes(DerivedKeySizeBytes);
    }
}
