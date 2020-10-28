using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionDemo
{
    public class Base64Helper
    {
        private static readonly Encoding Encoder = Encoding.UTF8;
        public static string EncodeBase64(string source)
        {
            string target = "";
            byte[] bytes = Encoder.GetBytes(source);
            try
            {
                target = Convert.ToBase64String(bytes);
            }
            catch
            {
                target = source;
            }
            return target;
        }

        public static string DecodeBase64(string result)
        {
            string decode = "";
            byte[] bytes = Convert.FromBase64String(result);
            try
            {
                decode = Encoder.GetString(bytes);
            }
            catch
            {
                decode = result;
            }
            return decode;
        }
    }
}
