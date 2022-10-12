using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string letters = "abcdefghijklmnopqrstuvwxyz";
        public int get_letter_index(char letter) 
        {
            int i;
            int ret = -1;
            for ( i = 0; i < 26; i++)
            {
                if (letter == this.letters[i]) 
                { 
                    return i;
                }
            }
            return ret; //-1
        }
        public string Encrypt(string plainText, int key)
        {
            int i;
            string cipher_txt = "";
            for ( i = 0; i < plainText.Length; i++) 
            {
                if (char.IsLetter(plainText[i]))
                {
                    int char_index = ((key + get_letter_index(plainText[i])) % 26);//(key + pt index )mod 26
                    //convert the char into integer

                    cipher_txt  += letters[char_index];
                    //concatinate C.T
                }
            }
            cipher_txt = cipher_txt.ToUpper();//cipher in upper case
            return cipher_txt;
        }
        public string Decrypt(string cipherText, int key)
        {
            string plain_txt = "";
            cipherText = cipherText.ToLower();
            int j;
            for ( j = 0; j < cipherText.Length; j++)
            {
                if (char.IsLetter(cipherText[j]))
                {
                    int char_index = ((get_letter_index(cipherText[j]) - key) % 26);

                    if (char_index < 0) char_index += 26;
                    plain_txt = plain_txt + letters[char_index];
                }
            }
            return plain_txt;
        }

        public int Analyse(string plainText, string cipherText) 
        {
            if (plainText.Length != cipherText.Length)
            {
                return -1;
            }
            int pt_start = get_letter_index(plainText[0]);
            int ct_start = get_letter_index(char.ToLower(cipherText[0]));


            //since CT = index of PT  +  Key
            //the   Key = CT          - index of PT  
            if (ct_start - pt_start < 0)
            {
                int x= (ct_start - pt_start) + 26;
                return x;
            }
            else
                return (ct_start - pt_start);
        }
    }
}
