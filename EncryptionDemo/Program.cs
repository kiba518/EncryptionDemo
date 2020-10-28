using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"MD5-64:{ MD5Helper.Get64Md5("Kiba518")}");
            Console.WriteLine($"MD5-32:{ MD5Helper.Get32Md5("Kiba518")}");
            Console.WriteLine($"SHA1:{ SHA1Helper.Sha1("Kiba518")}");
            string base64Str = Base64Helper.EncodeBase64("Kiba518");
            Console.WriteLine($"Base64编码:{ base64Str}");
            Console.WriteLine($"Base64解码:{ Base64Helper.DecodeBase64(base64Str)}");

            string key_8 = "abcdefgh";
            string desShortKeyStr = DESHelper.Encrypt("Kiba518", key_8);
            Console.WriteLine($"DES加密:{ desShortKeyStr}");
            Console.WriteLine($"DES解密:{ DESHelper.Decrypt(desShortKeyStr, key_8)}");

            string key_long = "abcdefgh1234567890";
            string desLongKeyStr = DESHelper.LongKeyEncrypt("Kiba518", key_long);
            Console.WriteLine($"DES-long Key加密:{ desLongKeyStr}");
            Console.WriteLine($"DES-long Key解密:{ DESHelper.LongKeyDESDecrypt(desLongKeyStr, key_long)}");

            string key_long_base64 = "abcdefgh";
            string desLongKeyStr_base64 = DESHelper.LongKeyWithBase64Encrypt("Kiba518", key_long_base64);
            Console.WriteLine($"DES-long Key WithBase64加密:{ desLongKeyStr_base64}");
            Console.WriteLine($"DES-long Key WithBase64解密:{ DESHelper.LongKeyWithBase64DESDecrypt(desLongKeyStr_base64, key_long_base64)}");

            //加密公钥  
            string publicKey = "<RSAKeyValue><Modulus>18+I2j3HU/fXQasRXOWGegP3dG75I/It2n42rgeIATeftBkoQNH73Rz0IYW++arqd0Yy5hFpNkqzY/dOmD+bDXWUheWA0P/dVZf+qeWwVV+iW3lRAU8SmnPcaD35Ic1jMEPFQVeX1zGI2ofD8aGodeSRA4+JKo+KLgyGVGDI+d0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            //解密私钥 
            string privateKey = "<RSAKeyValue><Modulus>18+I2j3HU/fXQasRXOWGegP3dG75I/It2n42rgeIATeftBkoQNH73Rz0IYW++arqd0Yy5hFpNkqzY/dOmD+bDXWUheWA0P/dVZf+qeWwVV+iW3lRAU8SmnPcaD35Ic1jMEPFQVeX1zGI2ofD8aGodeSRA4+JKo+KLgyGVGDI+d0=</Modulus><Exponent>AQAB</Exponent><P>2EEAI+cO1fyvmGpg3ywMLHHZ1/X3ZrF6xZBNM2AL7bJFVfL8RS8UznUCdsL/R/o1b+lGo1CetlI++n6IvYYwyw==</P><Q>/3muAXWOU3SMKFWSDpHUgeM9kZev0ekQDefRSayXM8q9ItkaWTOJcIN614A0UGdYE6VX1ztPgveQFzm0qJDy9w==</Q><DP>NM/i/eGewOmd5IYONFJogq4nOlOKYNz1E6yC/gn1v83qmuvlaevuk+EFggVrHKPhSvxYUOgOao45bSlbsZVE8w==</DP><DQ>MKU7w91dh3iWw4tfr1SHUWAytglbGi41t2Af0taBSARftUX/pWKR1hHDD0vDKlgzRjJiooIRps966WE8jChliw==</DQ><InverseQ>YEIfQArVNP27AJn3WOBswHP/+gJ6Bk434MZ80CJONp4b6e+Ilxd2dwloxGKNbGgCyaNJEFI5J8qYSNNe0KqPkw==</InverseQ><D>ZAscSPesqLtS+WlBMkxgy719AGfVbRl+sjQiSwjIvq+3hDjJVUtCs90RO10SDBF0gfhz7f2SRY3ZnXTu5VtPF9KEQyUaY0F6eXwz4YQNzJTI2c1o5SFXZP8Ynqwltg8gNIhMe8bB6nVgASeADBim22DlSFCzmD3vt1gTI8nxmO0=</D></RSAKeyValue>";
            string myname = "my name is Kiba518!my name is Kiba518!!!!43"; //最大长度43
            string rsaStr = RSAHelper.RSAEncrypt(publicKey, myname);
            Console.WriteLine($"RSA加密:{ rsaStr}");
            string dersaStr = RSAHelper.RSADecrypt(privateKey, rsaStr);
            Console.WriteLine($"RSA解密:{ dersaStr}");

            string mynameLong = "my name is Kiba518!my name is Kiba518!!!!43my name is Kiba518!my name is Kiba518!!!!43"; //最大长度43
            string rsalongStr = RSAHelper.SubRSAEncrypt(publicKey, mynameLong);
            Console.WriteLine($"RSA分段加密:{ rsalongStr}");
            string dersalongStr = RSAHelper.SubRSADecrypt(privateKey, rsalongStr);
            Console.WriteLine($"RSA分段解密:{ dersalongStr}");
            Console.ReadKey();

            
        }
        
    }
}
