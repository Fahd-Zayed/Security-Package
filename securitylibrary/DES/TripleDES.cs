using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DES;
namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES obj = new DES();
     

        public string Decrypt(string cipherText, List<string> key)
        {
            string pt = "";

            pt = obj.Decrypt(cipherText, key[1]);
            pt = obj.Encrypt(pt, key[0]);
            pt = obj.Decrypt(pt, key[1]);

            return pt;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string ct = "";

            ct = obj.Encrypt(plainText, key[0]);
            ct = obj.Decrypt(ct, key[1]);
            ct = obj.Encrypt(ct, key[0]);

            return ct;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}