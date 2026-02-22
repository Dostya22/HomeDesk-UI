using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HomeDesk_UI.Models;
using Konscious.Security.Cryptography;

namespace HomeDesk_UI.Services;

public class AuthService
{
    private readonly HttpClient _httpClient = new()
    {
        BaseAddress = new Uri("http://localhost:8000")
    };

    public async Task RegisterAsync(string email, string name, string password, string inviteCode)
    {
        //Generate Identity Keys (X25519)
        var x25519Curve = ECCurve.CreateFromFriendlyName("x25519");
        using var x25519 = ECDiffieHellman.Create(x25519Curve);

        var pubKeyRaw = GetRawPublicKey(x25519);
        var privKeyRaw = GetRawPrivateKey(x25519);

        // Derive Master Key using Argon2
        var salt = RandomNumberGenerator.GetBytes(16);
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 4,
            Iterations = 4,
            MemorySize = 65536
        };
        // Master key is used to decrypt secrets
        var masterKey = await argon2.GetBytesAsync(32);
        // Used to validate user login
        var loginHash = SHA256.HashData(masterKey);
        // Used to create master key on other devices in conjunction with password
        var (encPrivKey, privNonce) = EncryptAesGcm(privKeyRaw, masterKey);

        // Create and wrap the personal vault key
        var personalTeamKey = RandomNumberGenerator.GetBytes(32);
        var (wrappedTeamKey, teamNonce) = EncryptAesGcm(personalTeamKey, privKeyRaw);

        var request = new RegisterRequest
        {
            invite_code = inviteCode,
            email = email,
            name = name,
            password_hash = loginHash,
            password_salt = salt,
            public_key = pubKeyRaw,
            encrypted_private_key = encPrivKey,
            private_key_nonce = privNonce,
            wrapped_personal_key = wrappedTeamKey,
            personal_key_nonce = teamNonce
        };

        var json = JsonSerializer.Serialize(request);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");

        using var response = await _httpClient.PostAsync("/auth/signup", content);
        response.EnsureSuccessStatusCode();
    }

    /// Encrypts the specified data using AES-GCM encryption with the provided key.
    /// AES-GCM is a mode of operation for the Advanced Encryption Standard (AES)
    /// that provides both confidentiality and data integrity.
    /// <param name="data">
    ///     The plaintext data to encrypt. This must be a byte array containing the data to secure.
    /// </param>
    /// <param name="key">
    ///     The encryption key to use for AES-GCM. It must be a byte array of length 16, 24, or 32 bytes.
    /// </param>
    /// <returns>
    ///     A tuple containing the following:
    ///     1. The encrypted data, which consists of the concatenated ciphertext and authentication tag.
    ///     2. The nonce used during encryption, which is required for decryption.
    /// </returns>
    /// <exception cref="ArgumentException">
    ///     Thrown if the provided key is not of a valid size for AES-GCM encryption.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     Thrown if encryption fails due to internal issues with the cryptographic operation.
    /// </exception>
    private static (byte[] combined, byte[] nonce) EncryptAesGcm(byte[] data, byte[] key)
    {
        // AES-GCM requires a 12-byte nonce and a 16-byte tag
        using var aes = new AesGcm(key, 16);

        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        var tag = new byte[16];
        var ciphertext = new byte[data.Length];

        // Perform the encryption
        aes.Encrypt(nonce, data, ciphertext, tag);

        // We store the Tag at the end of the Ciphertext (Standard practice)
        // Result: [ Ciphertext (32 bytes) ] + [ Tag (16 bytes) ] = 48 bytes
        var combined = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, combined, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, combined, ciphertext.Length, tag.Length);

        return (combined, nonce);
    }

    private static byte[] GetRawPublicKey(ECDiffieHellman x25519)
    {
        // X25519 SubjectPublicKeyInfo is 44 bytes; the last 32 are the key.
        Span<byte> info = stackalloc byte[44];
        return x25519.PublicKey.TryExportSubjectPublicKeyInfo(info, out var written)
            ? info[(written - 32)..].ToArray()
            : throw new CryptographicException("Failed to export public key.");
    }

    private static byte[] GetRawPrivateKey(ECDiffieHellman x25519)
    {
        // X25519 PKCS8 is 48 bytes; the last 32 are the key.
        Span<byte> pkcs8 = stackalloc byte[48];
        return x25519.TryExportPkcs8PrivateKey(pkcs8, out var written)
            ? pkcs8[(written - 32)..].ToArray()
            : throw new CryptographicException("Failed to export private key.");
    }
}