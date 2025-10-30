using System.Security.Cryptography;
using System.Text;

namespace SecureStore.Security;

/// <summary>
/// Manages a 32-byte AES key persisted as a DPAPI-protected blob (CurrentUser).
/// The plaintext key is never written to disk.
/// </summary>
public sealed class KeyStore
{
    private readonly string _dirPath;
    private readonly string _protectedKeyPath;

    // App-specific extra entropy for DPAPI (constant per app).
    private static readonly byte[] s_appEntropy = Encoding.UTF8.GetBytes("SecureStore-App-Entropy-v1");

    public KeyStore(string? customDirectory = null)
    {
        _dirPath = customDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SecureStore");
        _protectedKeyPath = Path.Combine(_dirPath, "appkey.dpapi");
    }

    /// <summary>
    /// Ensures a DPAPI-protected key exists; returns the plaintext key in memory.
    /// </summary>
    public byte[] GetOrCreateKey()
    {
        Directory.CreateDirectory(_dirPath);

        if (File.Exists(_protectedKeyPath))
        {
            var protectedBlob = File.ReadAllBytes(_protectedKeyPath);
            return ProtectedData.Unprotect(protectedBlob, s_appEntropy, DataProtectionScope.CurrentUser);
        }
        else
        {
            byte[] key = RandomNumberGenerator.GetBytes(32); // 256-bit AES key
            try
            {
                byte[] protectedBlob = ProtectedData.Protect(key, s_appEntropy, DataProtectionScope.CurrentUser);
                using var fs = new FileStream(_protectedKeyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                fs.Write(protectedBlob, 0, protectedBlob.Length);
                return key;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
        }
    }
}
