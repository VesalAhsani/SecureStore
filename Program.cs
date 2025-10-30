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
            long newId = db.Insert(label, nonce, tag, ct);
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
                string recovered = crypto.Decrypt(rec.Value.label, rec.Value.nonce, rec.Value.tag, rec.Value.ciphertext);
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
  add <label> <plaintext>   Encrypt and store a secret
  get <id>                   Decrypt and display a secret
  list                       List entries (id, label, timestamp)
  delete <id>                Delete an entry
");
}
