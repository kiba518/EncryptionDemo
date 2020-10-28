using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
 
 
using System.Diagnostics;

namespace EncryptionDemo
{
    public class RSAHelper
    {
        private static readonly Encoding Encoder = Encoding.UTF8;
        #region 短字符串加密 
        /// <summary> 
        /// RSA解密 
        /// </summary> 
        /// <param name="xmlPrivateKey"></param> 
        /// <param name="enptStr"></param> 
        /// <returns></returns> 
        public static string RSADecrypt(string xmlPrivateKey, string enptStr)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPrivateKey);
            byte[] rgb = Convert.FromBase64String(enptStr);
            byte[] bytes = provider.Decrypt(rgb, RSAEncryptionPadding.OaepSHA1);
            return new UnicodeEncoding().GetString(bytes);
        }
        /// <summary> 
        /// RSA加密 待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：RSACryptoServiceProvider.KeySize / 8 - 11），而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：RSACryptoServiceProvider.KeySize / 8）。
        /// </summary> 
        /// <param name="xmlPublicKey"></param> 
        /// <param name="enptStr"></param> 
        /// <returns></returns> 
        public static string RSAEncrypt(string xmlPublicKey, string enptStr)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            byte[] bytes = new UnicodeEncoding().GetBytes(enptStr);
            return Convert.ToBase64String(provider.Encrypt(bytes, RSAEncryptionPadding.OaepSHA1));
        }
        #endregion

        #region 长字符串加密 
        /// <summary>
        /// 分段加密，应对长字符串
        /// </summary>
        /// <param name="xmlPublicKey"></param>
        /// <param name="enptStr"></param>
        /// <returns></returns>
        public static String SubRSAEncrypt(string xmlPublicKey, string enptStr)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            Byte[] bytes = Encoder.GetBytes(enptStr);
            int MaxBlockSize = provider.KeySize / 8 - 11;    //加密块最大长度限制

            if (bytes.Length <= MaxBlockSize)
                return Convert.ToBase64String(provider.Encrypt(bytes, false));

            using (MemoryStream PlaiStream = new MemoryStream(bytes))
            using (MemoryStream CrypStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[MaxBlockSize];
                int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);

                while (BlockSize > 0)
                {
                    Byte[] ToEncrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                    Byte[] Cryptograph = provider.Encrypt(ToEncrypt, false);
                    CrypStream.Write(Cryptograph, 0, Cryptograph.Length);

                    BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                }

                return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
            }

        }
        /// <summary>
        /// 分段解密，应对长字符串
        /// </summary>
        /// <param name="xmlPublicKey"></param>
        /// <param name="enptStr"></param>
        /// <returns></returns>
        public static String SubRSADecrypt(string xmlPublicKey, string enptStr)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            Byte[] bytes = Convert.FromBase64String(enptStr);
            int MaxBlockSize = provider.KeySize / 8;    //解密块最大长度限制

            if (bytes.Length <= MaxBlockSize)
                return Encoder.GetString(provider.Decrypt(bytes, false));

            using (MemoryStream CrypStream = new MemoryStream(bytes))
            using (MemoryStream PlaiStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[MaxBlockSize];
                int BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);

                while (BlockSize > 0)
                {
                    Byte[] ToDecrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);

                    Byte[] Plaintext = provider.Decrypt(ToDecrypt, false);
                    PlaiStream.Write(Plaintext, 0, Plaintext.Length);

                    BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);
                }

                return Encoder.GetString(PlaiStream.ToArray());
            }
        }
        #endregion
    }
}
