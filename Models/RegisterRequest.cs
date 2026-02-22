namespace HomeDesk_UI.Models;

public class RegisterRequest
{
    public string invite_code { get; set; } = string.Empty;
    public string email { get; set; } = string.Empty;
    public string name { get; set; } = string.Empty;
    public byte[] password_hash { get; set; } = [];
    public byte[] password_salt { get; set; } = [];
    public byte[] public_key { get; set; } = [];
    public byte[] encrypted_private_key { get; set; } = [];
    public byte[] private_key_nonce { get; set; } = [];
    public byte[] wrapped_personal_key { get; set; } = [];
    public byte[] personal_key_nonce { get; set; } = [];
}