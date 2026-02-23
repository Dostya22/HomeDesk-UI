using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HomeDesk_UI.Models;
using Konscious.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace HomeDesk_UI.Services;

/// <summary>
///     Provides authentication-related services, including user registration and cryptographic operations.
/// </summary>
public class AuthService
{
    /// <summary>
    ///     The HTTP client used for making requests to the authentication API.
    ///     Default base address is set to localhost:8000.
    /// </summary>
    private readonly HttpClient _httpClient = new()
    {
        BaseAddress = new Uri("http://localhost:8000")
    };

    /// <summary>
    ///     Registers a new user by generating cryptographic keys, deriving a master key from the password,
    ///     and sending a registration request to the API.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <param name="name">The user's full name.</param>
    /// <param name="password">The user's password, used for key derivation.</param>
    /// <param name="inviteCode">A valid invitation code required for signup.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="HttpRequestException">Thrown if the registration request fails.</exception>
    public async Task RegisterAsync(string email, string name, string password, string inviteCode)
    {
        // --- Step 1: Generate Identity Keys (X25519) ---
        // Using X25519 for Diffie-Hellman key exchange. 
        // These keys will be used for future secure communications and internal key wrapping.
        // BouncyCastle's implementation for cross-platform compatibility (X25519 support isn't native yet).
        var kpGen = new X25519KeyPairGenerator();
        kpGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = kpGen.GenerateKeyPair();

        // Extract the raw 32-byte public and private keys from the generated key pair.
        var pubKeyRaw = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        var privKeyRaw = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();

        // --- Step 2: Derive Master Key using Argon2id ---
        // Argon2id is a state-of-the-art password hashing algorithm designed to be resistant 
        // to GPU/ASIC cracking and side-channel attacks.
        // We generate a random 16-byte salt for each user to prevent rainbow table attacks.
        var salt = RandomNumberGenerator.GetBytes(16);
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 4, // Use 4 threads
            Iterations = 4, // Number of passes over memory
            MemorySize = 65536 // Use 64MB of RAM
        };

        // The master key is the primary secret derived from the user's password.
        // It's never sent to the server in its raw form.
        var masterKey = await argon2.GetBytesAsync(32);

        // --- Step 3: Create Login Hash and Encrypt Private Key ---
        // We hash the master key using SHA-256 to create a 'login hash'.
        // This hash is sent to the server to verify the user's password during login without revealing the master key.
        var loginHash = SHA256.HashData(masterKey);

        // We encrypt the user's X25519 private key using the master key.
        // This allows the user to recover their identity on other devices using their password.
        // AES-GCM provides both confidentiality and integrity.
        var (encPrivKey, privNonce) = EncryptAesGcm(privKeyRaw, masterKey);

        // --- Step 4: Create and Wrap Personal Vault Key ---
        // Each user has a unique 'personal team key' (or vault key) used to encrypt their data.
        // We generate this key randomly.
        var personalTeamKey = RandomNumberGenerator.GetBytes(32);

        // We 'wrap' (encrypt) this vault key using the user's X25519 private key.
        // This establishes the cryptographic hierarchy: Password -> Master Key -> Private Key -> Vault Key.
        var (wrappedTeamKey, teamNonce) = EncryptAesGcm(personalTeamKey, privKeyRaw);

        // --- Step 5: Send Registration Request ---
        // Construct the registration request with all the necessary cryptographic material.
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

        // Serialize to JSON and post to the /auth/signup endpoint.
        var json = JsonSerializer.Serialize(request);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");

        using var response = await _httpClient.PostAsync("/auth/signup", content);

        // Ensure the API call was successful; throws HttpRequestException on failure.
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
}