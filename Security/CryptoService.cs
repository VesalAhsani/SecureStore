using System.Security.Cryptography;
using System.Text;

namespace SecureStore.Security;

/// <summary>
/// AES-GCM encrypt/decrypt with data_label as AAD for integrity.
/// </summary>
public sealed class CryptoService : IDisposable
{
    private const int TagSize = 16; // bytes
    private readonly byte[] _key;
    private readonly AesGcm _aes;

    public CryptoService(byte[] key)
    {
        if (key is null || key.Length != 32)
            throw new ArgumentException("AES-256 key must be 32 bytes.", nameof(key));
        _key = key;

#if NET9_0_OR_GREATER
        _aes = new AesGcm(key, TagSize);
#else
#pragma warning disable SYSLIB0053
        _aes = new AesGcm(key); // On .NET 8 this is the supported ctor.
#pragma warning restore SYSLIB0053
#endif
    }

    public (byte[] nonce, byte[] tag, byte[] ciphertext) Encrypt(string dataLabel, string plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12); // 96-bit
        byte[] aad = Encoding.UTF8.GetBytes(dataLabel);
        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[TagSize];

        try
        {
            _aes.Encrypt(nonce, pt, ct, tag, aad);
            return (nonce, tag, ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pt);
        }
    }

    public string Decrypt(string dataLabel, byte[] nonce, byte[] tag, byte[] ciphertext)
    {
        byte[] aad = Encoding.UTF8.GetBytes(dataLabel);
        byte[] pt = new byte[ciphertext.Length];
        try
        {
            _aes.Decrypt(nonce, ciphertext, tag, pt, aad);
            return Encoding.UTF8.GetString(pt);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Decryption failed (tag mismatch or corruption).", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pt);
        }
    }

    public void Dispose()
    {
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_key);
    }
}
