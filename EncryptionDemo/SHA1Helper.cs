using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionDemo
{
    public class SHA1Helper
    {
        private static readonly Encoding Encoder = Encoding.UTF8;
        /// <summary>
        /// SHA1加密
        /// </summary>
        /// <param name="content">待加密的字符串</param> 
        /// <returns></returns>
        public static String Sha1(String content )
        {
            try
            {
                SHA1 sha1 = new SHA1CryptoServiceProvider();//创建SHA1对象
                byte[] bytes_in = Encoder.GetBytes(content);//将待加密字符串转为byte类型
                byte[] bytes_out = sha1.ComputeHash(bytes_in);//Hash运算
                sha1.Dispose();//释放当前实例使用的所有资源
                String result = BitConverter.ToString(bytes_out);//将运算结果转为string类型
                result = result.Replace("-", "").ToUpper();
                return result;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}
