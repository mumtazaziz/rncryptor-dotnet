using System.Security.Cryptography;
using System.Text;

namespace RNCryptor.Tests;

[TestClass]
public class Encryptor
{
    [TestMethod]
    public void PasswordBasedEncryption()
    {
        foreach (PasswordVector vector in Vectors.Password)
        {
            Cryptor cryptor = new()
            {
                Version = vector.Version,
                Password = vector.Password,
                EncryptionSalt = vector.EncryptionSalt,
                HMACSalt = vector.HMACSalt,
                IV = vector.IV,
            };
            using MemoryStream outputStream = new();
            using (CryptoStream cryptoStream = new(outputStream, cryptor.CreateEncryptor(), CryptoStreamMode.Write))
            {
                using MemoryStream inputStream = new(vector.Plaintext, false);
                inputStream.CopyTo(cryptoStream);
            }
            byte[] ciphertext = outputStream.ToArray();
            Assert.IsTrue(ciphertext.SequenceEqual(vector.Ciphertext));
        }
    }
}