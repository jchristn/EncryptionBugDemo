using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace EncryptionBugDemo
{
    internal class Program
    {
        static byte[] _Passphrase = Encoding.UTF8.GetBytes("0000000000000000");
        static byte[] _Salt = Encoding.UTF8.GetBytes("0000000000000000");
        static byte[] _Iv = Encoding.UTF8.GetBytes("0000000000000000");
        static int _PasswordIterations = 2;
        static int _KeySize = 256;

        static string _Json = "{\"GUID\":\"cce6eb38-0442-4b96-8791-06453e82db1e\",\"MerchantGUID\":\"89aa9d75-c78c-435d-a1ea-cce17770712b\",\"Brand\":\"Visa\",\"AccountNumber\":\"4123123412341234\",\"Last4\":\"1234\",\"ExpirationMonth\":12,\"ExpirationYear\":2024,\"NameOnCard\":\"JoelChristner\",\"CVV\":\"475\",\"CreatedUtc\":\"2021-11-17T17:28:26.9781146Z\"}";

        static void Main(string[] args)
        {
            byte[] cipher = SHA1Encrypt(Encoding.UTF8.GetBytes(_Json));
            Console.WriteLine("Cipher (base64) : " + Convert.ToBase64String(cipher));

            byte[] clear = SHA1Decrypt(cipher);
            Console.WriteLine("Clear (base64)  : " + Convert.ToBase64String(clear));
            Console.WriteLine("Clear (UTF8)    : " + Encoding.UTF8.GetString(clear));

            object obj = DeserializeJson<dynamic>(Encoding.UTF8.GetString(clear));
        }

        static byte[] SHA1Encrypt(byte[] clear)
        {
            // see http://www.obviex.com/samples/Encryption.aspx

            if (clear == null || clear.Length < 1) throw new ArgumentNullException(nameof(clear));

            PasswordDeriveBytes password = new PasswordDeriveBytes(_Passphrase, _Salt, "SHA1", _PasswordIterations);
            byte[] keyBytes = password.GetBytes(_KeySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, _Iv);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(clear, 0, clear.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        static byte[] SHA1Decrypt(byte[] cipher)
        {
            // see http://www.obviex.com/samples/Encryption.aspx

            if (cipher == null || cipher.Length < 1) throw new ArgumentNullException(nameof(cipher));

            PasswordDeriveBytes password = new PasswordDeriveBytes(_Passphrase, _Salt, "SHA1", _PasswordIterations);
            byte[] keyBytes = password.GetBytes(_KeySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, _Iv);

            using (MemoryStream ms = new MemoryStream(cipher))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    byte[] clear = new byte[cipher.Length];
                    int decryptedCount = cs.Read(clear, 0, clear.Length);
                    byte[] ret = new byte[decryptedCount];
                    Buffer.BlockCopy(clear, 0, ret, 0, decryptedCount);
                    return clear;
                }
            }
        }

        static string SerializeJson(object obj, bool pretty)
        {
            if (obj == null) return null;
            string json;

            if (pretty)
            {
                json = JsonConvert.SerializeObject(
                  obj,
                  Newtonsoft.Json.Formatting.Indented,
                  new JsonSerializerSettings
                  {
                      NullValueHandling = NullValueHandling.Ignore,
                      DateTimeZoneHandling = DateTimeZoneHandling.Utc,
                  });
            }
            else
            {
                json = JsonConvert.SerializeObject(obj,
                  new JsonSerializerSettings
                  {
                      NullValueHandling = NullValueHandling.Ignore,
                      DateTimeZoneHandling = DateTimeZoneHandling.Utc
                  });
            }

            return json;
        }

        static T DeserializeJson<T>(string json)
        {
            if (String.IsNullOrEmpty(json)) throw new ArgumentNullException(nameof(json));
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}
