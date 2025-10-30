# SecureStore - Encrypted SQLite with DPAPI (Windows, .NET 8)

A minimal Windows console app that stores secrets in SQLite only after AES-GCM encryption.
The AES-256 key is generated once and saved only as a DPAPI-protected blob (CurrentUser scope).

## Requirements
- Windows 10/11
- .NET 8 SDK

## Build & Run
dotnet restore
dotnet build -c Release
dotnet run -- add password "my super secret"
dotnet run -- list
dotnet run -- get 1

## How it works
- Key mgmt: Security/KeyStore.cs uses Windows DPAPI via ProtectedData to protect a 32-byte AES key.
- Encryption: Security/CryptoService.cs uses AES-GCM. data_label is AAD for integrity.
- Database: Data/DatabaseService.cs writes only nonce / tag / ciphertext to SQLite.
- CLI: Program.cs supports add, get, list, delete.

## Security notes
- Unique 12-byte nonce per record; 16-byte auth tag.
- Parameterized SQL to prevent injection.
- Sensitive buffers are zeroed where practical.
- The DPAPI-protected key blob lives at %AppData%\SecureStore\appkey.dpapi.