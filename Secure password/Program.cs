using System;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;

namespace secure_password
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string password = "SuperSecretPassword";
            string userId = "901248023";

            // Generate a new salt
            byte[] salt;
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                salt = new byte[16];
                rng.GetBytes(salt);
            }

            // Hash the password with the salt
            byte[] hash = HashPassword(password, salt);

            // Save user's salt and hash in the database
            SaveCredentials(userId, salt, hash);

            // To validate an entered password later
            bool isValid = ValidatePassword(userId, "PasswordToCheck");
            Console.WriteLine($"Password is valid: {isValid}");
        }

        static byte[] HashPassword(string password, byte[] salt)
        {
            int iterations = 10000;
            int keySize = 32;

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(keySize);
            }
        }

        static void SaveCredentials(string userId, byte[] salt, byte[] hash)
        {
            string connectionString = "Data Source=ZBC-S-985Y0;Initial Catalog=secure password;Integrated Security=True;TrustServerCertificate=True";

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "INSERT INTO Users (UserId, PasswordSalt, PasswordHash) VALUES (@UserId, @PasswordSalt, @PasswordHash)";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserId", userId);
                    command.Parameters.AddWithValue("@PasswordSalt", salt);
                    command.Parameters.AddWithValue("@PasswordHash", hash);

                    connection.Open();
                    command.ExecuteNonQuery();
                }
            }
        }

        static bool ValidatePassword(string userId, string enteredPassword)
        {
            string connectionString = "Data Source=ZBC-S-985Y0;Initial Catalog=secure password;Integrated Security=True;TrustServerCertificate=True";
            byte[] storedSalt;
            byte[] storedHash;

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "SELECT PasswordSalt, PasswordHash FROM Users WHERE UserId = @UserId";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserId", userId);

                    connection.Open();

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            storedSalt = (byte[])reader["PasswordSalt"];
                            storedHash = (byte[])reader["PasswordHash"];
                        }
                        else
                        {
                            throw new Exception("User not found.");
                        }
                    }
                }
            }

            byte[] hashOfEnteredPassword = HashPassword(enteredPassword, storedSalt);
            return hashOfEnteredPassword.SequenceEqual(storedHash);
        }
    }
}
