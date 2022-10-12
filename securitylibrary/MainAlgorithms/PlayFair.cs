using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public struct KOMatrices
    {
        public List<List<char>> O_M;
        public Dictionary<char, Tuple<int, int>> K_M;
    }
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public HashSet<char> ModifiedKey(string key)
        {
            string A_To_Z = "abcdefghiklmnopqrstuvwxyz" ;// no j
            HashSet<char> Matrix_Key = new HashSet<char>();
            int i;
            for (i = 0; i < key.Length; i++)
            {
                if (key[i] == 'j')
                    Matrix_Key.Add('i');
                else
                    Matrix_Key.Add(key[i]);
            }//key is added succsesfully in matrix(play fair example)
            for (i = 0; i < 25; i++)
            {
                Matrix_Key.Add(A_To_Z[i]); // j not exist!
            }//rest of alphapets are added to matrix
            return Matrix_Key;
            //here we have the full matrix filled
        }
        public KOMatrices KOFunc(HashSet<char> M_key)
        {
            int counter = 0;
            int i,j;
            Dictionary<char, Tuple<int, int>> K_Matrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> O_Matrix = new List<List<char>>();
            
            for ( i = 0; i < 5; i++)
            {
                List<char> temp_var = new List<char>();
                for ( j = 0; j < 5; j++)
                {
                    if (counter < 25)
                    {
                        K_Matrix.Add(M_key.ElementAt(counter), new Tuple<int, int>(i, j));
                        temp_var.Add(M_key.ElementAt(counter));
                        counter++;
                    }
                }
                O_Matrix.Add(temp_var);
            }
            KOMatrices koo_matrix = new KOMatrices();
            koo_matrix.K_M = K_Matrix;
            koo_matrix.O_M = O_Matrix;
            return koo_matrix;
        }

        public List<string> divideIt(string x)
        {
            int chunk_var = 100;
            List<string> big_string = new List<string>();
            for (int i = 0; i < x.Length; i += chunk_var)
            {
                if (i + chunk_var > x.Length)
                {
                    chunk_var = x.Length - i;
                }
                big_string.Add(x.Substring(i, chunk_var));
            }
            return big_string;
        }

        public string Decrypt(string cipherText, string key)
        {
            bool bool_flag = false;
            cipherText = cipherText.ToLower();
            List<string> small_sets = new List<string>();
            
            if (cipherText.Length > 100)
            {
                bool_flag = true;
                small_sets = divideIt(cipherText);
            }
            string F_PT = "";
            KOMatrices M_matrx = KOFunc(ModifiedKey(key));
            int j;
            for (j= 0; !bool_flag || j < small_sets.Count ; j++)
            {
                if (bool_flag)
                {
                    cipherText = small_sets[j];
                }
                
                string plain_text = "";
                bool_flag = true;
                for (int i = 0; i < cipherText.Length; i += 2)//get plain text from cipher text
                {
                    char ch1 = cipherText[i], ch2 = cipherText[i + 1];
                    //handle the three cases of decription
                    if (M_matrx.K_M[ch1].Item2 == M_matrx.K_M[ch2].Item2)
                    {
                        //same col
                        plain_text = plain_text + M_matrx.O_M[(M_matrx.K_M[ch1].Item1 + 4) % 5][M_matrx.K_M[ch1].Item2];
                        plain_text = plain_text + M_matrx.O_M[(M_matrx.K_M[ch2].Item1 + 4) % 5][M_matrx.K_M[ch2].Item2];
                    }
                    else if (M_matrx.K_M[ch1].Item1 == M_matrx.K_M[ch2].Item1)
                    {
                        //same row
                        plain_text = plain_text + M_matrx.O_M[M_matrx.K_M[ch1].Item1][(M_matrx.K_M[ch1].Item2 + 4) % 5];
                        plain_text = plain_text + M_matrx.O_M[M_matrx.K_M[ch2].Item1][(M_matrx.K_M[ch2].Item2 + 4) % 5];
                    }
                    else
                    {
                        //oppisite to diagonal
                        plain_text = plain_text + M_matrx.O_M[M_matrx.K_M[ch1].Item1][M_matrx.K_M[ch2].Item2];
                        plain_text = plain_text + M_matrx.O_M[M_matrx.K_M[ch2].Item1][M_matrx.K_M[ch1].Item2];
                    }
                }


                string final_ans = plain_text;//initially = PT and without x removal
                
                if (plain_text[plain_text.Length - 1] == 'x')
                {
                    //remove x from the end of text if exist 
                    final_ans = final_ans.Remove(plain_text.Length - 1);
                }

                
                int w = 0;//we want to check the existance of x:
                for (int i = 0; i < final_ans.Length; i++)
                { 
                    if (plain_text[i] == 'x')//if we found x
                    {
                        if (plain_text[i - 1] == plain_text[i + 1])//if the char before x and char after x the same means we add x in encription so remove it here
                        {
                            if (i + w < final_ans.Length && (i - 1) % 2 == 0)
                            {
                                final_ans = final_ans.Remove(i + w, 1);
                                w--;
                            }
                        }
                    }
                }
                F_PT += final_ans;
            }
            Console.WriteLine(F_PT);
            return F_PT;//finally we get the plain text from cipher text
        }


        public string Encrypt(string plainText, string key)
        {
            string Cipher_text = "";
            KOMatrices KOkey = KOFunc(ModifiedKey(key));
            for (int i = 0; i < plainText.Length - 1; i += 2)//check plain text
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }//if there is dublicate char in plain text, add x
            }

            int check = plainText.Length % 2;
            if (check == 1)//means that the plain text is odd (last char has no mate)
            {
                plainText += 'x';//add x at the end of P.T to be even
            }

            for (int i = 0; i < plainText.Length; i += 2)
            {
                //this loop handle the three cases encription
                char c1 = plainText[i], c2 = plainText[i + 1];
                if (KOkey.K_M[c1].Item2 == KOkey.K_M[c2].Item2) //same column
                {
                    Cipher_text += KOkey.O_M[(KOkey.K_M[c1].Item1 + 1) % 5][KOkey.K_M[c1].Item2];
                    Cipher_text += KOkey.O_M[(KOkey.K_M[c2].Item1 + 1) % 5][KOkey.K_M[c2].Item2];
                }
                else if (KOkey.K_M[c1].Item1 == KOkey.K_M[c2].Item1)//same row
                {
                    Cipher_text += KOkey.O_M[KOkey.K_M[c1].Item1][(KOkey.K_M[c1].Item2 + 1) % 5];
                    Cipher_text += KOkey.O_M[KOkey.K_M[c2].Item1][(KOkey.K_M[c2].Item2 + 1) % 5];
                }
                else //diagonal
                {
                    Cipher_text += KOkey.O_M[KOkey.K_M[c1].Item1][KOkey.K_M[c2].Item2];
                    Cipher_text += KOkey.O_M[KOkey.K_M[c2].Item1][KOkey.K_M[c1].Item2];
                }
            }


            Console.WriteLine(Cipher_text.ToUpper());
            Console.WriteLine("\n\n");
            return Cipher_text.ToUpper();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }
    }
}