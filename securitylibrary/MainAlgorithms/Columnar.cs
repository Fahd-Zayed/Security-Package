using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {

            int key_lenght = 0;
            int count = 0;
            cipherText = cipherText.ToLower();
            int flag = 0; //check variable
            int i, j, k;
            for (i = 4; i < 8; i++)//fn get No. of columns (key count)
            {
                if (plainText.Length % i == 0)
                {
                    key_lenght = i;
                }
            }

            int rows = plainText.Length / key_lenght;//get row count

            char[,] first_matrix = new char[rows, key_lenght];//plain text matrix
            char[,] second_matrix = new char[rows, key_lenght];//cipher text matrix

            List<int> key_sequence = new List<int>(key_lenght);


            for (i = 0; i < rows; i++)//fill the matrix of plain text
            {
                for (j = 0; j < key_lenght; j++)
                {
                    if (count < plainText.Length)
                        first_matrix[i, j] = plainText[count];
                    if (count >= plainText.Length)
                    {
                        if (first_matrix.Length > plainText.Length)
                            first_matrix[i, j] = 'x';
                    }
                    count++;
                }
            }
            count = 0;

            //fill the cipher matrix 
            for (i = 0; i < key_lenght; i++)
            {
                for (j = 0; j < rows; j++)//fill by col
                {
                    if (count == plainText.Length)
                        break;
                    second_matrix[j, i] = cipherText[count];
                    count++;
                }
            }


            for (i = 0; i < key_lenght; i++)
            {
                for (k = 0; k < key_lenght; k++)
                {
                    for (j = 0; j < rows; j++)
                    {
                        if (first_matrix[j, i] == second_matrix[j, k])
                        {
                            flag++;
                        }
                        if (flag == rows)
                            key_sequence.Add(k + 1);
                    }
                    flag = 0;
                }
            }// compare plain matrix with cipher matrix to get key sequence

            if (key_sequence.Count == 0)//no key found
            {
                for (i = 0; i < key_lenght + 2; i++)
                {
                    key_sequence.Add(0);
                }
            }
            return key_sequence;
        }


        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToUpper();
            int cell_count = cipherText.Length; //cells count
            if (cell_count % key.Count != 0)
            {
                cell_count += key.Count;
            }// to complete the cells count 

            double rows = cell_count / key.Count; //col is refactored by row
            int c = (int)(rows);
            string plain_text = "";
            char[,] encryption = new char[c, key.Count];//2d array (rows = c, key = key.count)
            int key_value = 0;
            int tmp_var = 0;
            int i, j;

            for (i = 0; i < key.Count; i++)//this fn fill the 2d array with cipher text
            {
                key_value = key.IndexOf(i + 1);// ex : key 1 9 4 8

                for (j = 0; j < rows; j++)
                {
                    if (tmp_var < cipherText.Length)//fill till the cipher text is complete
                    {
                        encryption[j, key_value] = cipherText[tmp_var];//fill 2d matrix by the key order
                        tmp_var++;
                    }
                }
            }

            for (i = 0; i < rows; i++)// read the plain text row by row
            {
                for (j = 0; j < key.Count; j++)
                {
                    plain_text = plain_text + encryption[i, j];
                }
            }

            return plain_text.ToUpper();//return plain text
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int cols = key.Count;
            int no_of_rows = (int)Math.Ceiling((double)plainText.Length / cols);//get No. of rows 
            string complete_matrix;
            int y, i, j;

            if (plainText.Length != no_of_rows * cols)
            {
                y = (no_of_rows * cols) - plainText.Length;//y is the Number of missing value 
                complete_matrix = new string('x', y);
                plainText += complete_matrix;
            }//append x to the missing values

            List<List<char>> table_matrix = new List<List<char>>();
            SortedDictionary<int, string> final_cip = new SortedDictionary<int, string>();//sorted added
            string cipher_text = "";

            for (i = 0; i < no_of_rows; i++)
            {
                table_matrix.Add(new List<char>());
            }//bygzh al table 3la 3dd al rows 34an ymlaha al5twa algya


            int count = 0;
            for (i = 0; i < no_of_rows; i++)
            {
                for (j = 0; j < cols && count < plainText.Length; j++)
                {
                    table_matrix[i].Add(plainText[count]);
                    count++;
                }
            }// bymla almatrix bl plain text row by row 
            //matrix is ready

            for (i = 0; i < cols; i++)
            {
                string tmp = "";
                for (j = 0; j < no_of_rows; j++)
                {
                    tmp += table_matrix[j][i]; //get col by col
                    final_cip[key[i]] = tmp;  //put in dictionary to collect in string
                }
            }

            for (i = 1; i <= final_cip.Count; i++)
            {
                cipher_text += final_cip[i];// get the final Cipher text
            }
            Console.WriteLine(cipher_text);
            return cipher_text.ToUpper();
        }
    }
}