# SecureStore - Encrypted SQLite with DPAPI (Windows, .NET 8)

A minimal Windows console app that stores secrets in SQLite only after AES-GCM encryption.
The AES-256 key is generated once and saved only as a DPAPI-protected blob (CurrentUser scope).

## Requirements
- Windows 10/11
- .NET 8 SDK

## Build & Run
```
dotnet restore
dotnet build -c Release
dotnet run -- add password "my super secret"
dotnet run -- list
dotnet run -- get 1
```
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

## Integrity demo
1) dotnet run -- add note "attack me"
2) dotnet run -- list  (note the id)
3) dotnet run -- tamper <id>
4) dotnet run -- get <id>  # should show 'Decryption error'

## Evaluator Steps (Windows) for Dear Hassan

One-time prerequisites (Windows 10/11)
```
winget install Microsoft.DotNet.SDK.8
winget install Git.Git
# Optional (for DB inspection)
winget install SQLite.sqlite
```

Clone & build
```
git clone https://github.com/VesalAhsani/SecureStore.git
cd SecureStore
dotnet build -c Release
```

Clean slate (so first insert is id=1)
```
Remove-Item -Recurse -Force "$env:APPDATA\SecureStore" -ErrorAction SilentlyContinue
```

End-to-end test
```
dotnet run -- add password "hello world"   # expect: Inserted id=1
dotnet run -- list                         # expect: 1  password  <UTC time>
dotnet run -- get 1                        # expect: Label: password / Plaintext: hello world
```

Exact schema (single encrypted_data BLOB)
```
sqlite3 "$env:APPDATA\SecureStore\securestore.db" ".schema entries"
```

Ciphertext only in the DB (no plaintext)
```
sqlite3 "$env:APPDATA\SecureStore\securestore.db" "SELECT id,data_label,length(encrypted_data) FROM entries;"
sqlite3 "$env:APPDATA\SecureStore\securestore.db" "SELECT id, substr(hex(encrypted_data),1,32) FROM entries WHERE id=1;"
```

Key management via DPAPI (CurrentUser)
```
dir "$env:APPDATA\SecureStore"
# Expect: appkey.dpapi (protected key blob), securestore.db
```

Integrity check (AES-GCM tag + label as AAD)
```
sqlite3 "$env:APPDATA\SecureStore\securestore.db" "UPDATE entries SET data_label='changed' WHERE id=1;"
dotnet run -- get 1
# Expect: Decryption error (tag mismatch or corruption)
```

Publish & run the EXE (optional)
```
dotnet publish -c Release -r win-x64 --self-contained false
.\bin\Release\net8.0-windows\win-x64\publish\SecureStore.exe list
```


