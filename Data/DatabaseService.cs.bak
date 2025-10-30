using Microsoft.Data.Sqlite;

namespace SecureStore.Data;

public sealed class DatabaseService
{
    private readonly string _connectionString;

    public DatabaseService(string dbPath)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Default
        }.ToString();
        EnsureCreated();
    }

    private void EnsureCreated()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  data_label TEXT NOT NULL,
  nonce BLOB NOT NULL,
  tag BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_utc TEXT NOT NULL
);";
        cmd.ExecuteNonQuery();
    }

    public long Insert(string dataLabel, byte[] nonce, byte[] tag, byte[] ciphertext)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO entries (data_label, nonce, tag, ciphertext, created_utc)
VALUES ($label, $nonce, $tag, $ct, $ts);
SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$label", dataLabel);
        cmd.Parameters.AddWithValue("$nonce", nonce);
        cmd.Parameters.AddWithValue("$tag", tag);
        cmd.Parameters.AddWithValue("$ct", ciphertext);
        cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
        var id = (long)(cmd.ExecuteScalar() ?? 0L);
        return id;
    }

    public IEnumerable<(long id, string label, byte[] nonce, byte[] tag, byte[] ciphertext, DateTime createdUtc)> List()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, data_label, nonce, tag, ciphertext, created_utc FROM entries ORDER BY id;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            yield return (
                reader.GetInt64(0),
                reader.GetString(1),
                (byte[])reader[2],
                (byte[])reader[3],
                (byte[])reader[4],
                DateTime.Parse(reader.GetString(5), null, System.Globalization.DateTimeStyles.RoundtripKind)
            );
        }
    }

    public (string label, byte[] nonce, byte[] tag, byte[] ciphertext)? GetById(long id)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT data_label, nonce, tag, ciphertext FROM entries WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            return (
                reader.GetString(0),
                (byte[])reader[1],
                (byte[])reader[2],
                (byte[])reader[3]
            );
        }
        return null;
    }

    public int Delete(long id)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM entries WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteNonQuery();
    }
}
