using SecureStore.Security;
using SecureStore.Data;

try
{
    var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    var appDir = Path.Combine(appData, "SecureStore");
    Directory.CreateDirectory(appDir);

    string dbPath = Path.Combine(appDir, "securestore.db");

    var keyStore = new KeyStore(appDir);
    byte[] key = keyStore.GetOrCreateKey();

    using var crypto = new CryptoService(key);
    var db = new DatabaseService(dbPath);

    if (args.Length == 0)
    {
        PrintHelp();
        return;
    }

    var cmd = args[0].ToLowerInvariant();
    switch (cmd)
    {
        case "add":
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: add <label> <plaintext>");
                return;
            }
            string label = args[1];
            string plaintext = string.Join(' ', args.Skip(2));
            var (nonce, tag, ct) = crypto.Encrypt(label, plaintext);

            // Pack nonce(12) || tag(16) || ciphertext into one blob
            byte[] blob = new byte[nonce.Length + tag.Length + ct.Length];
            Buffer.BlockCopy(nonce, 0, blob, 0, nonce.Length);
            Buffer.BlockCopy(tag,   0, blob, nonce.Length, tag.Length);
            Buffer.BlockCopy(ct,    0, blob, nonce.Length + tag.Length, ct.Length);

            long newId = db.Insert(label, blob);
            Console.WriteLine($"Inserted id={newId}");
            break;

        case "get":
            if (args.Length != 2 || !long.TryParse(args[1], out long getId))
            {
                Console.WriteLine("Usage: get <id>");
                return;
            }
            var rec = db.GetById(getId);
            if (rec is null)
            {
                Console.WriteLine("Not found.");
                return;
            }
            try
            {
                byte[] blob2 = rec.Value.encryptedBlob;
                if (blob2.Length < 12 + 16)
                {
                    Console.WriteLine("Corrupted record.");
                    return;
                }
                byte[] nonce2 = new byte[12];
                byte[] tag2   = new byte[16];
                byte[] ct2    = new byte[blob2.Length - 12 - 16];

                Buffer.BlockCopy(blob2, 0, nonce2, 0, 12);
                Buffer.BlockCopy(blob2, 12, tag2, 0, 16);
                Buffer.BlockCopy(blob2, 12 + 16, ct2, 0, ct2.Length);

                string recovered = crypto.Decrypt(rec.Value.label, nonce2, tag2, ct2);
                Console.WriteLine($"Label: {rec.Value.label}\nPlaintext: {recovered}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Decryption error: {ex.Message}");
            }
            break;

        case "list":
            foreach (var row in db.List())
            {
                Console.WriteLine($"{row.id}\t{row.label}\t{row.createdUtc:o}");
            }
            break;

        case "delete":
            if (args.Length != 2 || !long.TryParse(args[1], out long delId))
            {
                Console.WriteLine("Usage: delete <id>");
                return;
            }
            int affected = db.Delete(delId);
            Console.WriteLine(affected == 0 ? "Not found." : "Deleted.");
            break;

        default:
            PrintHelp();
            break;
    }

    System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Fatal: {ex.Message}\n{ex}");
}

static void PrintHelp()
{
    Console.WriteLine(@"SecureStore – commands:
  add <label> <plaintext>   Encrypt and store a secret (packed into encrypted_data)
  get <id>                   Decrypt and display a secret
  list                       List entries (id, label, timestamp)
  delete <id>                Delete an entry
");
}
