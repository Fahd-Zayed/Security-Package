using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            List<int> probable_keys = new List<int>();

            char second = cipherText[1];
            int j,negative=-1,n=0;


            for (j= 0; j < plainText.Length; j++)
            {
                if (plainText[j] == second) { probable_keys.Add(j); } //computerScience 
                                                              //CmUESINEOPTRCEC

                                                            //Computer Spience
                                                            //CpECNOURICMTSEE
                                                            //key? 3
            }
            for ( j= 0; j < probable_keys.Count; j++)//chose the right key
            {
                string str = Encrypt(plainText, probable_keys[j]).ToLower(); //cipher text with depth i to compare with given cipher text
                if (String.Equals ( cipherText , str))
                    return probable_keys[j];
            }
            return negative;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int ct_len= cipherText.Length;
            int plain_text_len;

            plain_text_len = (int) Math.Ceiling ( (double) ct_len / key); //get coulmns

            string ret= Encrypt(cipherText, plain_text_len).ToLower();
            return ret;
        }

        public string Encrypt(string plainText, int key)
        {
            
            String.Join(plainText, plainText.Split(' '));//remove spaces
            List<List<char>> carrytable = new List<List<char>>();//carry matrix before get the CT

            int No_of_col,pt_len = plainText.Length;

            No_of_col = (int)Math.Ceiling((double)pt_len / key);//No. of columns
            int count = 0, C_i;
            string cipher = "";
            
            for (C_i= 0; C_i < key; C_i++)
            {
                carrytable.Add(new List<char>());
            }//byghz almatrix

            for ( C_i = 0; C_i < No_of_col; C_i++)//fill the matrix by column
            {
                for (int C_j = 0; C_j < key && C_j < pt_len; C_j++)
                {
                    carrytable[C_j].Add(plainText[count]);
                    count++;
                    if (count == plainText.Length)
                    {
                        break;
                    }     
                }
            }

            for ( C_i = 0; C_i < carrytable.Count; C_i++)//get matrix row by row
            {
                for (int C_j = 0; C_j < carrytable[C_i].Count; C_j++)
                {
                    cipher += carrytable[C_i][C_j];
                }
            }
            string ret= cipher.ToUpper();
            return ret;//return cipher text
        }
    }
}


