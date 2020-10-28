using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionDemo
{
    public class DESHelper
    {
        #region DES加密
        #region 长密钥Key base64编码    
        public static string LongKeyWithBase64Encrypt(string str, string longKey)
        {
            string encryptKeyall = Convert.ToString(longKey);    //定义密钥  
            if (encryptKeyall.Length < 9)
            {
                for (; ; )
                {
                    if (encryptKeyall.Length < 9)
                        encryptKeyall += encryptKeyall;
                    else
                        break;
                }
            }
            string key = encryptKeyall.Substring(0, 8);
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();   //实例化加/解密类对象   
            des.Mode = CipherMode.ECB;//java默认是ECB
            des.Padding = PaddingMode.PKCS7;
            des.Key = Encoding.UTF8.GetBytes(key); //定义字节数组，用来存储密钥    
            des.IV = Encoding.UTF8.GetBytes(key);
            byte[] data = Encoding.UTF8.GetBytes(str);//定义字节数组，用来存储要加密的字符串  
            MemoryStream ms = new MemoryStream(); //实例化内存流对象    
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);  //向加密流中写入数据      
            cs.FlushFinalBlock();              //释放加密流      
            StringBuilder ret = new StringBuilder(); 
            return Convert.ToBase64String(ms.ToArray());//返回加密后的字符串  
        }
        public static string LongKeyWithBase64DESDecrypt(string str, string longKey)
        {
            string encryptKeyall = Convert.ToString(longKey);    //定义密钥  
            if (encryptKeyall.Length < 9)
            {
                for (; ; )
                {
                    if (encryptKeyall.Length < 9)
                        encryptKeyall += encryptKeyall;
                    else
                        break;
                }
            }
            string encryptKey = encryptKeyall.Substring(0, 8);

            byte[] key = Encoding.UTF8.GetBytes(encryptKey);
            //byte[] keyIV = key;
            byte[] inputByteArray = Convert.FromBase64String(str);

            DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            // java 默认的是ECB模式，PKCS5padding；c#默认的CBC模式，PKCS7padding 所以这里我们默认使用ECB方式
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.PKCS7;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(key, key), CryptoStreamMode.Write);

            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            return Encoding.UTF8.GetString(ms.ToArray());

        }
        #endregion

        #region 长密钥Key     
        public static string LongKeyEncrypt(string str, string longKey)
        {
            string encryptKeyall = Convert.ToString(longKey);    //定义密钥  
            if (encryptKeyall.Length < 9)
            {
                for (; ; )
                {
                    if (encryptKeyall.Length < 9)
                        encryptKeyall += encryptKeyall;
                    else
                        break;
                }
            }
            string key = encryptKeyall.Substring(0, 8);
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();   //实例化加/解密类对象   
            des.Mode = CipherMode.ECB;//java默认是ECB
            des.Padding = PaddingMode.PKCS7;
            des.Key = Encoding.UTF8.GetBytes(key); //定义字节数组，用来存储密钥    
            des.IV = Encoding.UTF8.GetBytes(key);
            byte[] data = Encoding.UTF8.GetBytes(str);//定义字节数组，用来存储要加密的字符串  
            MemoryStream ms = new MemoryStream(); //实例化内存流对象    
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);  //向加密流中写入数据      
            cs.FlushFinalBlock();              //释放加密流       
            StringBuilder ret = new StringBuilder();
            foreach (byte b in ms.ToArray())
            {
                ret.AppendFormat("{0:X2}", b);
            }
            ret.ToString();
            return ret.ToString();
        }
        public static string LongKeyDESDecrypt(string str, string longKey)
        {
            string encryptKeyall = Convert.ToString(longKey);    //定义密钥  
            if (encryptKeyall.Length < 9)
            {
                for (; ; )
                {
                    if (encryptKeyall.Length < 9)
                        encryptKeyall += encryptKeyall;
                    else
                        break;
                }
            }
            string encryptKey = encryptKeyall.Substring(0, 8);
            DESCryptoServiceProvider des = new DESCryptoServiceProvider(); 
            byte[] inputByteArray = new byte[str.Length / 2];
            for (int x = 0; x < str.Length / 2; x++)
            {
                int i = (Convert.ToInt32(str.Substring(x * 2, 2), 16));
                inputByteArray[x] = (byte)i;
            } 
            des.Key = Encoding.UTF8.GetBytes(encryptKey);
            des.IV = Encoding.UTF8.GetBytes(encryptKey);
            // java 默认的是ECB模式，PKCS5padding；c#默认的CBC模式，PKCS7padding 所以这里我们默认使用ECB方式
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.PKCS7;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);

            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            StringBuilder ret = new StringBuilder();
            return System.Text.Encoding.Default.GetString(ms.ToArray());

        }
        #endregion
        #region 8位密钥Key
        /// <summary>
        /// 
        /// </summary>
        /// <param name="str"></param>
        /// <param name="shortKey">需要8位，即12345678，这样的八个字符</param>
        /// <returns></returns>
        public static string Encrypt(string str, string shortKey)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;//java默认是ECB
            des.Padding = PaddingMode.PKCS7; 
            des.Key = Encoding.UTF8.GetBytes(shortKey);
            des.IV = Encoding.UTF8.GetBytes(shortKey);
            byte[] data = Encoding.UTF8.GetBytes(str);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            StringBuilder ret = new StringBuilder();
            foreach (byte b in ms.ToArray())
            {
                ret.AppendFormat("{0:X2}", b);
            }
            ret.ToString();
            return ret.ToString();
        }

        public static string Decrypt(string str, string shortKey)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;//java默认是ECB
            des.Padding = PaddingMode.PKCS7;
            byte[] inputByteArray = new byte[str.Length / 2];
            for (int x = 0; x < str.Length / 2; x++)
            {
                int i = (Convert.ToInt32(str.Substring(x * 2, 2), 16));
                inputByteArray[x] = (byte)i;
            }
            des.Key = Encoding.UTF8.GetBytes(shortKey);
            des.IV = Encoding.UTF8.GetBytes(shortKey);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            StringBuilder ret = new StringBuilder();
            return System.Text.Encoding.Default.GetString(ms.ToArray());
        }

        #endregion
        #endregion
    }
}
