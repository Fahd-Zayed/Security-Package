using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int clength = cipherText.Length;
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            string temp = "";

            for (int i = 0; i < clength; i++)
            {
                key = key + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i])) + 26) % 26];
            }//key stream m3ana

            temp = temp + key[0];
            int klength = key.Length;//keystream length
            for (int i = 1; i < klength; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, temp)))
                {
                    return temp;
                }
                temp = temp + key[i];// H E L L O
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int temp = 0;
            string key_stream = "";
            int ctlength = cipherText.Length;
            string plaintext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            key_stream = key;
            while (key_stream.Length != cipherText.Length)
            {
                key_stream = key_stream + alphabet[((cipherText[temp] - key_stream[temp]) + 26) % 26];
                temp++;
            }
            for (int i = 0; i < ctlength; i++)
            {
                plaintext = plaintext + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(key_stream[i])) + 26) % 26];
            }
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            int temp = 0;
            string key_stream = "";
            int plength = plainText.Length;
            string ciphertext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            key_stream = key;
            while (key_stream.Length != plainText.Length)
            {
                key_stream += plainText[temp];
                temp++;
            }//key stream is now ready

            for (int i = 0; i < plength; i++)
            {
                ciphertext = ciphertext + alphabet[((alphabet.IndexOf(plainText[i]) + alphabet.IndexOf(key_stream[i]))) % 26];
            }
            return ciphertext;
        }
    }
}
