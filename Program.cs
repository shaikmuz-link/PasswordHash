using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BCryptEncryption = BCrypt.Net.BCrypt;

namespace PasswordHelper
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string _password = string.Empty;

            if (args.Length != 1)
            {
                Console.WriteLine("Usage: CsvHashUpdater <path to csv file>");
                return;
            }
            string filePath = args[0];
            CsvProcessor csvProcessor = new CsvProcessor();

            try
            {
                List<PasswordEntry> entries = csvProcessor.ReadCsv(filePath);
                foreach (var entry in entries)
                {
                    entry.Hash = ComputeHash(entry.Password);
                }
                csvProcessor.WriteCsv(filePath, entries);
                Console.WriteLine("CSV file updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }

            Console.WriteLine(_password);
            Console.ReadLine();
        }

        private static string ComputeHash(string _password)
        {
            MD5EncryptionProvider iEncryptProvider = new MD5EncryptionProvider();
            _password = iEncryptProvider.GeneratePassword(_password);

            BCryptEncryptionProvider bCryptEncryptionProvider = new BCryptEncryptionProvider();
            _password = bCryptEncryptionProvider.GeneratePassword(_password, 12);
            return _password;
        }
    }

    public class PasswordEntry
    {
        public string Password { get; set; }
        public string Hash { get; set; }
    }

    public class CsvProcessor
    {
        public List<PasswordEntry> ReadCsv(string filePath)
        {
            var entries = new List<PasswordEntry>();

            using (var reader = new StreamReader(filePath))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var columns = line.Split(',');

                    // Skip the header row
                    if (columns[0] == "Password" && columns[1] == "Hash")
                        continue;

                    entries.Add(new PasswordEntry
                    {
                        Password = columns[0],
                        Hash = columns.Length > 1 ? columns[1] : string.Empty
                    });
                }
            }

            return entries;
        }

        public void WriteCsv(string filePath, List<PasswordEntry> entries)
        {
            using (var writer = new StreamWriter(filePath))
            {
                // Write the header row
                writer.WriteLine("Password,Hash");

                // Write each entry
                foreach (var entry in entries)
                {
                    writer.WriteLine($"{entry.Password},{entry.Hash}");
                }
            }
        }
    }

    public class BCryptEncryptionProvider
    {
        public string GeneratePassword(string _password, int _noOfIteration)
        {
            var salt = this.GenerateRandom(_noOfIteration);
            return BCryptEncryption.HashPassword(_password, salt);
        }
        private string GenerateRandom(int _noofround)
        {
            return BCryptEncryption.GenerateSalt(_noofround);
        }

        public bool ValidatePassword(string _password, string _encryptedPassword)
        {
            return BCryptEncryption.Verify(_password, _encryptedPassword);
        }
    }

    public class MD5EncryptionProvider
    {
        private readonly MD5CryptoServiceProvider md5Provider;

        public MD5EncryptionProvider()
        {
            md5Provider = new MD5CryptoServiceProvider();
        }

        public string GeneratePassword(string password, int noOfIteration = 0)
        {
            StringBuilder hash = new StringBuilder();

            byte[] bytes = md5Provider.ComputeHash(new UTF8Encoding().GetBytes(password));

            for (int i = 0; i < bytes.Length; i++)
            {
                hash.Append(bytes[i].ToString("x2"));
            }

            return string.Format("0x{0}", hash.ToString().ToUpper());
        }

        public bool ValidatePassword(string password, string encryptedPassword)
        {
            var encryptthegivenpassword = GeneratePassword(password);

            return encryptthegivenpassword.Equals(encryptedPassword, StringComparison.OrdinalIgnoreCase);
        }
    }

}