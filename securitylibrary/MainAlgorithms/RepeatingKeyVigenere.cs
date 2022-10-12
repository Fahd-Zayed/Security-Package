using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string tmp_var = "", chars = "abcdefghijklmnopqrstuvwxyz", the_key = "";
            int counter_i;
            for ( counter_i= 0 ; counter_i < cipherText.Length; counter_i++)
            {
                the_key += chars[((chars.IndexOf(cipherText[counter_i]) - chars.IndexOf(plainText[counter_i])) + 26) % 26];
            }//key stream m3ana
            tmp_var  += the_key[0];
            int Length_of_key = the_key.Length;//len. of key stream
            for (counter_i = 1; counter_i < Length_of_key; counter_i++)
            {
                if (cipherText.Equals(Encrypt(plainText, tmp_var))) //compairs 2 string
                    return tmp_var;
                tmp_var += the_key[counter_i];
            }
            return tmp_var;
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int CT_LEN = cipherText.Length;
            string A_toZ = "abcdefghijklmnopqrstuvwxyz";
            string final_PT = "";
            int tmp_var = 0, i=0;
            while (key.Length != CT_LEN)
            {
                key += key[tmp_var];
                tmp_var++;
            }// to get key_stream

            for (i = 0; i < CT_LEN; i++)
            {
                final_PT += A_toZ[((A_toZ.IndexOf(cipherText[i]) - A_toZ.IndexOf(key[i])) + 26) % 26];
            }
            return final_PT;
        }
        public string Encrypt(string plainText, string key)
        {
            int j=0, tmp_var = 0;
            string Final_CT = "";
            string A_to_Z = "abcdefghijklmnopqrstuvwxyz";
            while (key.Length != plainText.Length)//fn to set length of keyword = key stream
            {
                key = key + key[tmp_var];//temp initialy =0;
                tmp_var++;
            }
            for (j = 0; j < plainText.Length; j++)
            {
                Final_CT += A_to_Z[( (A_to_Z.IndexOf(plainText[j]) + A_to_Z.IndexOf(key[j]))) % 26];
            }
            return Final_CT;
        }
    }
}