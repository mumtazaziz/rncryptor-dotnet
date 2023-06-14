using System;
namespace RNCryptor.Tests
{
    internal class Vectors
    {
        public static readonly KdfVector[] Kdf = new KdfVector[] {
        new KdfVector(
            title: "One byte",
            version: FormatVersion.V3,
            password: "a",
            salt: Convert.FromBase64String("AQIDBAUGBwg="),
            key: Convert.FromBase64String("/GMrDKayPv+ancPg5YUWf1oyiRbtGfg1WL47qYKHl80=")
        ),
        new KdfVector(
            title: "Short password",
            version: FormatVersion.V3,
            password: "thepassword",
            salt: Convert.FromBase64String("AgMEBQYHCAE="),
            key: Convert.FromBase64String("DqhPUlIxDcPjp2B8M7/R61gIBftoKTAF2iEDfM9JliY=")
        ),
        new KdfVector(
            title: "Passphrase",
            version: FormatVersion.V3,
            password: "this is a bit longer password",
            salt: Convert.FromBase64String("AwQFBgcIAQI="),
            key: Convert.FromBase64String("cTQ6yx6WdbAWrGXc/l3awuV+2cNVZf27LdbSzv4mPVs=")
        ),
        new KdfVector(
            title: "Long passphrase",
            version: FormatVersion.V3,
            password: "$$$it was the epoch of belief, it was the epoch of incredulity; it was the season of Light, it was the season of Darkness; it was the spring of hope, it was the winter of despair; we had everything before us, we had nothing before us; we were all going directly to Heaven, we were all going the other way.",
            salt: Convert.FromBase64String("BAUGBwgBAgM="),
            key: Convert.FromBase64String("EbUsUMv0W+amNqMUK4wwuFpiRIFKfUPjdFfzjeRsZzU=")
        ),
        new KdfVector(
            title: "Multibyte",
            version: FormatVersion.V3,
            password: "中文密码",
            salt: Convert.FromBase64String("BQYHCAECAwQ="),
            key: Convert.FromBase64String("0vwyN9SmlmjKg9lpws2hrGw2hHkrZkSxqQsgUgByFd0=")
        ),
        new KdfVector(
            title: "Mixed language",
            version: FormatVersion.V3,
            password: "中文密码 with a little English, too.",
            salt: Convert.FromBase64String("BgcIAQIDBAU="),
            key: Convert.FromBase64String("Rr2l9GWYKkdAxyi8FMXeXMf8TurwqkG7m56ElUUtr/8=")
        ),
    };
        public static readonly PasswordVector[] Password = new PasswordVector[] {
        new PasswordVector(
            title: "Multi-block",
            version: FormatVersion.V2,
            password: "password",
            encryptionSalt: Convert.FromBase64String("lwdtxmG24M4="),
            hmacSalt: Convert.FromBase64String("naO7Q9lbzUU="),
            iv: Convert.FromBase64String("7jltOeNC/9tnmycNzZxVfA=="),
            plaintext: Convert.FromBase64String("VGhpcyBpcyBhIGxvbmdlciB0ZXN0IHZlY3RvciBpbnRlbmRlZCB0byBiZSBsb25nZXIgdGhhbiBvbmUgYmxvY2su"),
            ciphertext: Convert.FromBase64String("AgGXB23GYbbgzp2ju0PZW81F7jltOeNC/9tnmycNzZxVfDcFX//MG2Y7HmuMVpTbuW2Xo6wPo/NV22ZoxaiioG8QBWzpI4SmGKNb8PqethKwtPpy90n3bi9yjBZXTcLxW3zsF4bSkcITX5Mt3Fo02er9a0X5lJGsI8NCma8L5opD5ugRO7dI+8GbytY46nmwcwk=")
        ),
        new PasswordVector(
            title: "All fields empty or zero (with one-byte password)",
            version: FormatVersion.V3,
            password: "a",
            encryptionSalt: Convert.FromBase64String("AAAAAAAAAAA="),
            hmacSalt: Convert.FromBase64String("AAAAAAAAAAA="),
            iv: Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAA=="),
            plaintext: Convert.FromBase64String(""),
            ciphertext: Convert.FromBase64String("AwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALMDm+Mc1+zl51T1yNoXADZmMTroqJ3c+OPLQf3BMLIynb4H1vTTLDTgUMi9fpM7Eg==")
        ),
        new PasswordVector(
            title: "One byte",
            version: FormatVersion.V3,
            password: "thepassword",
            encryptionSalt: Convert.FromBase64String("AAECAwQFBgc="),
            hmacSalt: Convert.FromBase64String("AQIDBAUGBwg="),
            iv: Convert.FromBase64String("AgMEBQYHCAkKCwwNDg8AAQ=="),
            plaintext: Convert.FromBase64String("AQ=="),
            ciphertext: Convert.FromBase64String("AwEAAQIDBAUGBwECAwQFBgcIAgMEBQYHCAkKCwwNDg8AAaH4cw4L9IDre3D2kKvyHgKVFBZK08R0pRswx+qhylRbfePeWwEKy60KmhOFffaWqA==")
        ),
        new PasswordVector(
            title: "Exactly one block",
            version: FormatVersion.V3,
            password: "thepassword",
            encryptionSalt: Convert.FromBase64String("AQIDBAUGBwA="),
            hmacSalt: Convert.FromBase64String("AgMEBQYHCAE="),
            iv: Convert.FromBase64String("AwQFBgcICQoLDA0ODwABAg=="),
            plaintext: Convert.FromBase64String("ASNFZ4mrze8="),
            ciphertext: Convert.FromBase64String("AwEBAgMEBQYHAAIDBAUGBwgBAwQFBgcICQoLDA0ODwABAg5Df+gJMJwD/VOkdRMemhl4uOrvV29grbjOIyCEm6MtdCkAQ4uol9IiEMdsNchJ3w==")
        ),
        new PasswordVector(
            title: "More than one block",
            version: FormatVersion.V3,
            password: "thepassword",
            encryptionSalt: Convert.FromBase64String("AgMEBQYHAAE="),
            hmacSalt: Convert.FromBase64String("AwQFBgcIAQI="),
            iv: Convert.FromBase64String("BAUGBwgJCgsMDQ4PAAECAw=="),
            plaintext: Convert.FromBase64String("ASNFZ4mrze8BI0Vn"),
            ciphertext: Convert.FromBase64String("AwECAwQFBgcAAQMEBQYHCAECBAUGBwgJCgsMDQ4PAAECA+AbvaXfLKitrOOPbFiNKR4D+VG3jTQXvCgWWB3Gt2fxouV1l1ErGOFjjyEjX6WSjA==")
        ),
        new PasswordVector(
            title: "Multibyte password",
            version: FormatVersion.V3,
            password: "中文密码",
            encryptionSalt: Convert.FromBase64String("AwQFBgcAAQI="),
            hmacSalt: Convert.FromBase64String("BAUGBwgBAgM="),
            iv: Convert.FromBase64String("BQYHCAkKCwwNDg8AAQIDBA=="),
            plaintext: Convert.FromBase64String("I0VniavN7wEjRWcB"),
            ciphertext: Convert.FromBase64String("AwEDBAUGBwABAgQFBgcIAQIDBQYHCAkKCwwNDg8AAQIDBIqeCL3sHEv+E+gfuF8AmrPduROH6AnErYbZ6KYBRVdxZle9MX1LtqdkRhWz3kAjQQ==")
        ),
        new PasswordVector(
            title: "Longer text and password",
            version: FormatVersion.V3,
            password: "It was the best of times, it was the worst of times; it was the age of wisdom, it was the age of foolishness;",
            encryptionSalt: Convert.FromBase64String("BAUGBwABAgM="),
            hmacSalt: Convert.FromBase64String("BQYHCAECAwQ="),
            iv: Convert.FromBase64String("BgcICQoLDA0ODwABAgMEBQ=="),
            plaintext: Convert.FromBase64String("aXQgd2FzIHRoZSBlcG9jaCBvZiBiZWxpZWYsIGl0IHdhcyB0aGUgZXBvY2ggb2YgaW5jcmVkdWxpdHk7IGl0IHdhcyB0aGUgc2Vhc29uIG9mIExpZ2h0LCBpdCB3YXMgdGhlIHNlYXNvbiBvZiBEYXJrbmVzczsgaXQgd2FzIHRoZSBzcHJpbmcgb2YgaG9wZSwgaXQgd2FzIHRoZSB3aW50ZXIgb2YgZGVzcGFpcjsgd2UgaGFkIGV2ZXJ5dGhpbmcgYmVmb3JlIHVzLCB3ZSBoYWQgbm90aGluZyBiZWZvcmUgdXM7IHdlIHdlcmUgYWxsIGdvaW5nIGRpcmVjdGx5IHRvIEhlYXZlbiwgd2Ugd2VyZSBhbGwgZ29pbmcgdGhlIG90aGVyIHdheS4KCg=="),
            ciphertext: Convert.FromBase64String("AwEEBQYHAAECAwUGBwgBAgMEBgcICQoLDA0ODwABAgMEBdVkx6mdqSGm58QHioJkHZVHlVEoMWeiyB8xq4DJ19i+t3ARHezT49Kbvffrv8XxCsh+flW/taf0h7zTmDVwXoO5wEnG1pUr4BH43bGhT8DJJXON4BfmKx1iHM23Xyk30KGnDkTYQ7nGEDfe4pmLK710C5ECMu6nGWEWiDj2mVuZZBc7NMC80xGiyH4nFjCSi64wGo9HA6wq5GmfPChavxxVrDJLBzqViuUu6MO9aPkZwJ6xzSgUKhmWqebL/19PTh26B9Kf9mhg25iVpIIzFAyiSUGdYwRkSNsbD0JSpuTtuUf9AHHR5SvBVgBiL6VIpnc5Y2GBUHl6ioDlkkRt9ZJtC/0ytUS3lvM1lWc5T3fnsXGy+bxfLK96D6wNp9BNaoZ0TW4G0C++FdD1gKHVvRatkTSAA2ETWNy0rJmQlV9su7+xhZQdS0txzn+bpu/BJwt4CIOLbHt+8X6NuRmzT6w=")
        )
    };
    }
    internal class KdfVector
    {
        private readonly string _title;
        private readonly FormatVersion _version;
        private readonly string _password;
        private readonly byte[] _salt;
        private readonly byte[] _key;
        public KdfVector(string title, FormatVersion version, string password, byte[] salt, byte[] key)
        {
            _title = title;
            _version = version;
            _password = password;
            _salt = salt;
            _key = key;
        }
        public string Title => _title;
        public FormatVersion Version => _version;
        public string Password => _password;
        public byte[] Salt => _salt;
        public byte[] Key => _key;
    }
    internal class KeyVector
    {
        private readonly string _title;
        private readonly FormatVersion _version;
        private readonly byte[] _encryptionKey;
        private readonly byte[] _hmacKey;
        private readonly byte[] _iv;
        private readonly byte[] _plaintext;
        private readonly byte[] _ciphertext;
        public KeyVector(string title, FormatVersion version, byte[] encryptionKey, byte[] hmacKey, byte[] iv, byte[] plaintext, byte[] ciphertext)
        {
            _title = title;
            _version = version;
            _encryptionKey = encryptionKey;
            _hmacKey = hmacKey;
            _iv = iv;
            _plaintext = plaintext;
            _ciphertext = ciphertext;
        }
        public string Title => _title;
        public FormatVersion Version => _version;
        public byte[] EncryptionKey => _encryptionKey;
        public byte[] HMACKey => _hmacKey;
        public byte[] IV => _iv;
        public byte[] Plaintext => _plaintext;
        public byte[] Ciphertext => _ciphertext;
    }
    internal class PasswordVector
    {
        private readonly string _title;
        private readonly FormatVersion _version;
        private readonly string _password;
        private readonly byte[] _encryptionSalt;
        private readonly byte[] _hmacSalt;
        private readonly byte[] _iv;
        private readonly byte[] _plaintext;
        private readonly byte[] _ciphertext;
        public PasswordVector(string title, FormatVersion version, string password, byte[] encryptionSalt, byte[] hmacSalt, byte[] iv, byte[] plaintext, byte[] ciphertext)
        {
            _title = title;
            _version = version;
            _password = password;
            _encryptionSalt = encryptionSalt;
            _hmacSalt = hmacSalt;
            _iv = iv;
            _plaintext = plaintext;
            _ciphertext = ciphertext;
        }
        public string Title => _title;
        public FormatVersion Version => _version;
        public string Password => _password;
        public byte[] EncryptionSalt => _encryptionSalt;
        public byte[] HMACSalt => _hmacSalt;
        public byte[] IV => _iv;
        public byte[] Plaintext => _plaintext;
        public byte[] Ciphertext => _ciphertext;
    }
}