using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public Dictionary<char, char> KeyDictionary(string key, string Operation)
        {
            Dictionary<char, char> Dictionaryy = new Dictionary<char, char>();
            Ceaser C = new Ceaser(); //object from function ceaser
            int i;
            for (i = 0; i < 26; i++) // for loop for adding the 26 alphabet in dictionaryy
            {
                if (Operation == "encrypt") //encryption
                {
                    Dictionaryy.Add(C.letters[i], key[i]);
                }
                else //decryption
                {
                    Dictionaryy.Add(key[i], C.letters[i]);
                }
            }
            return Dictionaryy;
        }
        public string Analyse(string plainText, string cipherText)
        {
            SortedDictionary<char, char> Table_of_keys = new SortedDictionary<char, char>();
            Dictionary<char, bool> alphabet = new Dictionary<char, bool>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int i,j;
            for (i = 0; i < plainText.Length ; i++)
            {
                if (!Table_of_keys.ContainsKey(plainText[i]))
                {
                    Table_of_keys.Add(plainText[i], cipherText[i]); 
                    alphabet.Add(cipherText[i], true);
                }
            }
            if (Table_of_keys.Count != 26)
            {
                Ceaser objectt = new Ceaser();
                string letters = objectt.letters;
                for ( i = 0; i < 26; i++)
                {
                    if (!Table_of_keys.ContainsKey(letters[i]))
                    {
                        for ( j = 0; j < 26; j++)
                        {
                            if (!alphabet.ContainsKey(letters[j]))
                            {
                                alphabet.Add(letters[j], true);
                                Table_of_keys.Add(letters[i], letters[j]);
                                break;
                            }
                        }
                    }
                }
            }
            string K_value = "";
            foreach (var item in Table_of_keys)
            {
                K_value = K_value + item.Value;
            }
            return K_value;
        }

        public string Decrypt(string cipherText, string key)
        {
            int i;
            Dictionary<char, char> Table_of_keys = KeyDictionary(key, "decrypt"); //dictionary of keys
            cipherText = cipherText.ToLower();
            string Plain_Text = "";
            for (i = 0; i < cipherText.Length; i++) //for loop to check on cipher text
            {
                if (char.IsLetter(cipherText[i])) //if cipher text is all letters
                {
                    Plain_Text += Table_of_keys[cipherText[i]]; //retur it to plain text and concatenate it
                }
            }
            return Plain_Text; // return plain text
        }
        public string Encrypt(string plainText, string key)
        {
            int i;
            Dictionary<char, char> Table_of_keys = KeyDictionary(key, "encrypt");
            string Cipher_Text = "";
            for (i = 0; i < plainText.Length; i++) //for loop to check on plaintext
            {
                if (char.IsLetter(plainText[i])) //if all plain text is letters
                {
                    Cipher_Text = Cipher_Text + Table_of_keys[plainText[i]]; //convert it to cipher text and concatenate it
                }
            }
            return Cipher_Text.ToUpper(); //return cipher text
        }
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string letterfrequency = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, int> alphabetFrequency = new Dictionary<char, int>();
            SortedDictionary<char, char> Table_of_keys = new SortedDictionary<char, char>();
            int j;
            string str_key = "";
            //all letters start with frequency 0
            for ( j = 0; j < cipher.Length; j++)
            {
                if (!alphabetFrequency.ContainsKey(cipher[j]))
                    alphabetFrequency.Add(cipher[j], 0);
                else
                    alphabetFrequency[cipher[j]]++; //counting frequency
            }
            alphabetFrequency = alphabetFrequency.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            //sorting from asc to dec then reverse it to be from decs to asc
            int n = 0;
            foreach (var item in alphabetFrequency)
            {
                Table_of_keys.Add(item.Key, letterfrequency[n]);
                n++;
            }
            int i;
            for (i= 0; i < cipher.Length; i++)
            {
                str_key = str_key + Table_of_keys[cipher[i]];
            }
            return str_key;
        }
    }
}