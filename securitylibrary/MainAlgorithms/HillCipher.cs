using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int[,] matrix1 = new int[2, plainText.Count / 2];
            int i = 0,p=0;
            int col1 = 0, col2 = 0;
            int C_i, c_j, k, n;
            int ptlen = plainText.Count;
            for (C_i = 0; C_i < ptlen/ 2; C_i++)
            {
                for (c_j = 0; c_j < 2; c_j++)
                {
                    matrix1[c_j, C_i] = plainText[i];
                    i++;
                }

            }

            int[,] inverseKey = new int[2, 2];
            inverseKey[0, 0] = 0;
            int[,] sub_matriix = new int[2, 2];
            for (k = 0; k < ptlen - 1 / 2; k++)
            {
                for (C_i = k + 1; C_i < ptlen / 2; C_i++)
                {
                    for (c_j = 0; c_j < 2; c_j++)
                    {
                        sub_matriix[c_j, 0] = matrix1[c_j, k];
                    }

                    for (n = 0; n < 2; n++)
                    {
                        sub_matriix[n, 1] = matrix1[n, C_i];
                    }
                    int determinate;
                    determinate = sub_matriix[0, 0] * sub_matriix[1, 1] - sub_matriix[0, 1] * sub_matriix[1, 0];
                    if (determinate > 25)
                    {
                        determinate = determinate % 26;
                    }
                        
                    if (determinate < 0)
                        while (determinate < 0)
                            determinate += 26;

                    p = check(determinate, 26);
                    if (p == 0)
                    {
                        continue;
                    }
                    else
                    {
                        col1 = k;
                        col2 = C_i;
                        if (p > 25) {
                            p = p % 26;
                        }
                            
                        if (p < 0)
                            while (p < 0)
                                p += 26;

                        inverseKey[0, 0] = p * sub_matriix[1, 1];
                        inverseKey[0, 1] = -p * sub_matriix[1, 0];
                        inverseKey[1, 0] = -p * sub_matriix[0, 1];
                        inverseKey[1, 1] = p * sub_matriix[0, 0];
                        C_i = k = 7;
                        break;
                    }


                }
            }
            if (inverseKey[0, 0] == 0)
                throw new InvalidAnlysisException();
            for (C_i = 0; C_i < 2; C_i++)
            {
                for (c_j = 0; c_j < 2; c_j++)
                {
                    if (inverseKey[C_i, c_j] > 25)
                        inverseKey[C_i, c_j] = inverseKey[C_i, c_j] % 26;
                    else if (inverseKey[C_i, c_j] < 0)
                        while (inverseKey[C_i, c_j] < 0)
                            inverseKey[C_i, c_j] += 26;
                }

            }

            int tmp_var = inverseKey[0, 1];
            inverseKey[0, 1] = inverseKey[1, 0];
            inverseKey[1, 0] = tmp_var;

            i = 0;
            int[,] cipher = new int[2, cipherText.Count / 2];
            for (C_i = 0; C_i < cipherText.Count / 2; C_i++)
            {
                for (c_j = 0; c_j < 2; c_j++)
                {
                    cipher[c_j, C_i] = cipherText[i];
                    i++;
                }
            }

            List<int> subCipher = new List<int>();
            int[,] two_by2_matrix = new int[2, 2];
            for (C_i = 0; C_i < 2; C_i++)
                two_by2_matrix[C_i, 0] = cipher[C_i, col1];
            for (C_i = 0; C_i < 2; C_i++)
                two_by2_matrix[C_i, 1] = cipher[C_i, col2];
            for (C_i = 0; C_i < 2; C_i++)
            {
                for (c_j = 0; c_j < 2; c_j++)
                    subCipher.Add(two_by2_matrix[C_i, c_j]);
            }

            List<int> the_key = new List<int>();
            i = 0;
            int res_Of_multiply = 0;
            for (C_i = 0; C_i < 3; C_i += 2)
            {
                for (c_j = 0; c_j < 2; c_j++)
                {
                    for (k = 0; k < 2; k++)
                    {
                        res_Of_multiply += subCipher[i] * inverseKey[k, c_j];
                        i++;
                    }
                    if (res_Of_multiply > 25)
                        res_Of_multiply = res_Of_multiply % 26;
                    i -= 2;
                    the_key.Add(res_Of_multiply);
                    res_Of_multiply = 0;
                }
                i += 2;
            }
            return the_key;
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int Size_of_matrix;
            Size_of_matrix = (int)Math.Sqrt(key.Count);
            int[,] Matrix_of_key = new int[Size_of_matrix, Size_of_matrix];
            List<int> PT = new List<int>();
            int determnant = 0,res_of_multiply = 0,valu = 0, count = 0, C_i;

            for (C_i = 0; C_i < Size_of_matrix; C_i++)//fill key matrix
            {
                for (int j = 0; j < Size_of_matrix; j++)
                {
                    Matrix_of_key[C_i, j] = key[count];
                    count++;
                }
            }

            if (Size_of_matrix == 2)//2x2 matrix only
            {
                determnant = Matrix_of_key[0, 0] * Matrix_of_key[1, 1] - Matrix_of_key[0, 1] * Matrix_of_key[1, 0];//calc determnant

                if (Math.Abs(determnant) != 1)
                    throw new InvalidAnlysisException();

                determnant = 1 / determnant;
                //handle co matrix by42lb aly osad b3d w by7ot -ve ll diagonal altany
                int tmp_var = Matrix_of_key[0, 0];
                Matrix_of_key[0, 0] = Matrix_of_key[1, 1];
                Matrix_of_key[1, 1] = tmp_var;
                Matrix_of_key[0, 1] = -Matrix_of_key[0, 1];
                Matrix_of_key[1, 0] = -Matrix_of_key[1, 0];
                int c_ii;
                for ( c_ii = 0; c_ii < Size_of_matrix; c_ii++)//multibly det inv by co matrix
                {
                    for (int j = 0; j < Size_of_matrix; j++)
                    {
                        Matrix_of_key[c_ii, j] *= determnant;
                    }
                } //now we have k^ -1

                count = 0;
                int c = 0;
                for ( c_ii = 0; c_ii < cipherText.Count; c_ii += Size_of_matrix) // PT = (key^ -1 x CT mod 26) 
                {
                    for ( c = 0; c < Size_of_matrix; c++)
                    {
                        for (int k = 0; k < Size_of_matrix; k++)
                        {
                            res_of_multiply += Matrix_of_key[c, k] * cipherText[count];
                            count++;
                        }
                        if (res_of_multiply > 25)
                        {
                            res_of_multiply = res_of_multiply % 26;
                        }
                       
                        while (res_of_multiply < 0)
                            res_of_multiply += 26;//to be in range of chars

                        count -= Size_of_matrix;
                        PT.Add(res_of_multiply);
                        res_of_multiply = 0;
                    }
                    count += Size_of_matrix;
                }
                return PT;
            }

            determnant = determnant_calculation(Matrix_of_key, Size_of_matrix);//more than 2x2 matrix

            if (determnant > 25)//K-1ij ={b x (-1)i+j * Dij mod 26} mod 26
                determnant = determnant % 26;
            ///////////////////////////////////////////////////////////////////////

            while (determnant < 0)
                determnant += 26;
            
            int b;
            b = check(determnant, 26);

            if (b > 25)
                b = b % 26;
           
            while (b < 0)
                b += 26;
            

            int[,] inverse_of_key = new int[Size_of_matrix, Size_of_matrix];
            int C_I,C_J;
            for ( C_I = 0; C_I < Size_of_matrix; C_I++)
            {
                for ( C_J = 0; C_J < Size_of_matrix; C_J++)
                {
                    determnant = Calc_determnant(Matrix_of_key, Size_of_matrix, C_I, C_J);//K-1ij ={b x (-1)i+j * Dij mod 26} mod 26
                    if (determnant > 25)
                        determnant = determnant % 26;
                    else if (determnant < 0)
                    {
                        while (determnant < 0)
                            determnant += 26;
                    }//K-1ij ={b x (-1)i+j * Dij mod 26} mod 26
                    valu = b * (int)Math.Pow(-1, C_I + C_J) * determnant;
                    if (valu > 25)
                        valu = valu % 26;
                   
                    while (valu < 0)
                        valu += 26;
                    
                    inverse_of_key[C_I, C_J] = valu;
                }
            }
            int[,] Trans_key = new int[Size_of_matrix, Size_of_matrix];
            int c_i,c_j;
            for ( c_i = 0; c_i < Size_of_matrix; c_i++)//transpose final matrix
            {
                for ( c_j = 0; c_j < Size_of_matrix; c_j++)
                {
                    Trans_key[c_i, c_j] = inverse_of_key[c_j, c_i];
                }
            }
            count = 0;
            for (int i = 0; i < cipherText.Count; i += Size_of_matrix)//k^-1 * C.Ti mod 26  //trans_key * C.Ti mod 26
            {
                int j;
                for ( j = 0; j < Size_of_matrix; j++)
                {
                    for (int c = 0; c < Size_of_matrix; c++)
                    {
                        res_of_multiply += Trans_key[j, c] * cipherText[count];
                        count++;
                    }
                    if (res_of_multiply > 25)
                        res_of_multiply = res_of_multiply % 26;
                    count -= Size_of_matrix;
                    PT.Add(res_of_multiply);
                    res_of_multiply = 0;

                }
                count += Size_of_matrix;
            }

            return PT;
        }
        public int Calc_determnant(int[,] matriix, int siize, int i, int j)
        {
            List<List<int>> indexs = new List<List<int>>();

            int count = 0;
            for (int ii = 0; ii < siize; ii++)
            {
                for (int jj = 0; jj < siize; jj++)
                {
                    indexs.Add(new[] { ii, jj }.ToList());
                    count++;
                }
            }

            for (int ii = 0; ii < indexs.Count; ii++)
            {
                if (indexs[ii][0] == i || indexs[ii][1] == j)
                {
                    indexs.RemoveAt(ii);
                    ii--;
                }
            }
            int res = matriix[indexs[0][0], indexs[0][1]] * matriix[indexs[3][0], indexs[3][1]] -
                matriix[indexs[1][0], indexs[1][1]] * matriix[indexs[2][0], indexs[2][1]];
            return res;
        }
        public int Greatest_common_devisor(int x, int y)
        {
            int tmp = 0;
            if (y == 0)
                return x;
            tmp = x % y;
            x = y;
            y = tmp;
            return Greatest_common_devisor(x, y);
        }

        private int check(int b, int m)
        {
            int x = 1, y = 0, z = m, x2 = 0, y2 = 1, z2 = b;

            while (true)
            {
                if (z2 == 0)
                    return 0;
                if (z2 == 1)
                    return y2;
                int QQ = z / z2;
                int T1 = x - (QQ * x2), T2 = y - (QQ * y2), T3 = z - (QQ * z2);
                x = x2;
                y = y2;
                z = z2;
                x2 = T1;
                y2 = T2;
                z2 = T3;
            }

            return 0;
        }


        public int determnant_calculation(int[,] MtrX, int siize)
        {
            int determnant;
            if (siize == 2)
                return MtrX[0, 0] * MtrX[1, 1] - MtrX[0, 1] * MtrX[1, 0];

            determnant = MtrX[0, 0] * (MtrX[1, 1] * MtrX[2, 2] - MtrX[1, 2] * MtrX[2, 1]) -
                MtrX[0, 1] * (MtrX[1, 0] * MtrX[2, 2] - MtrX[1, 2] * MtrX[2, 0]) +
                MtrX[0, 2] * (MtrX[1, 0] * MtrX[2, 1] - MtrX[1, 1] * MtrX[2, 0]);

            return determnant;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int count = 0;
            int size_of_matrix;
             size_of_matrix = (int)Math.Sqrt(key.Count);//get matrix size //3
            int res_of_multiply = 0;
            List<int> final_CT = new List<int>();
            int[,] key_matrix = new int[size_of_matrix, size_of_matrix];

            for (int C_i = 0; C_i < size_of_matrix; C_i++)//fn to fill the matrix 3x3 by key (key matrix)
            {
                for (int C_J = 0; C_J < size_of_matrix; C_J++)
                {
                    key_matrix[C_i, C_J] = key[count];
                    count++;
                }
            }

            count = 0;
            int pt_len= plainText.Count;
            for (int C_i = 0; C_i < pt_len; C_i += size_of_matrix)//matrix multiblication mod 26
            {
                for (int C_j = 0; C_j < size_of_matrix; C_j++)
                {
                    for (int i = 0; i < size_of_matrix; i++)
                    {
                        res_of_multiply += key_matrix[C_j, i] * plainText[count];
                        count++;
                    }
                    if (res_of_multiply > 25)
                        res_of_multiply = res_of_multiply % 26;
                    count -= size_of_matrix;//to start from next col
                    final_CT.Add(res_of_multiply);//add Ct column by column
                    res_of_multiply = 0; //reset
                }
                count += size_of_matrix;//next row with next col from plain text
            }
            return final_CT;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int size_of_matrix = (int)Math.Sqrt(plain3.Count);
            int determnant = 0, PP = 0;
            int[,] plain_Text_Matrix = new int[size_of_matrix, size_of_matrix];
            int counters = 0;
            for (int C_i = 0; C_i < size_of_matrix; C_i++)
            {
                for (int C_J = 0; C_J < size_of_matrix; C_J++)
                {
                    plain_Text_Matrix[C_J, C_i] = plain3[counters];
                    counters++;
                }
            }

            int[,] sub_PT = new int[size_of_matrix, size_of_matrix];
            sub_PT[0, 0] = 0;
            for (int C_i = 0; C_i < size_of_matrix; C_i++)
            {
                for (int C_j = C_i + 1; C_j < size_of_matrix; C_j++)
                {
                    for (int k = C_j + 1; k < size_of_matrix; k++)
                    {

                        for (int a = 0; a < size_of_matrix; a++)
                            sub_PT[a, 0] = plain_Text_Matrix[a, C_i];
                        for (int d = 0; d < size_of_matrix; d++)
                            sub_PT[d, 1] = plain_Text_Matrix[d, C_j];
                        for (int e = 0; e < size_of_matrix; e++)
                            sub_PT[e, 2] = plain_Text_Matrix[e, k];

                        determnant = determnant_calculation(sub_PT, size_of_matrix);
                        if (determnant > 25)
                            determnant = determnant % 26;
                        else if (determnant < 0)
                            while (determnant < 0)
                                determnant += 26;

                        PP = check(determnant, 26);
                        if (PP == 0)
                            continue;
                        else if (PP > 25)
                            PP = PP % 26;
                        else if (PP < 0)
                            while (PP < 0)
                                PP += 26;
                    }
                }
            }

            if (sub_PT[0, 0] == 0)
                throw new InvalidAnlysisException();
            int[,] inv_Plain = new int[size_of_matrix, size_of_matrix];
            int ValU = 0;
            for (int C_i = 0; C_i < size_of_matrix; C_i++)
            {
                for (int C_j = 0; C_j < size_of_matrix; C_j++)
                {
                    determnant = Calc_determnant(sub_PT, size_of_matrix, C_i, C_j);
                    if (determnant > 25)
                        determnant = determnant % 26;
                    else if (determnant < 0)
                    {
                        while (determnant < 0)
                            determnant += 26;
                    }
                    ValU = PP * (int)Math.Pow(-1, C_i + C_j) * determnant;
                    if (ValU > 25)
                        ValU = ValU % 26;
                    else if (ValU < 0)
                    {
                        while (ValU < 0)
                            ValU += 26;
                    }
                    inv_Plain[C_i, C_j] = ValU;
                }
            }

            int[,] TransPlain = new int[size_of_matrix, size_of_matrix];
            for (int C_i = 0; C_i < size_of_matrix; C_i++)
            {
                for (int C_j = 0; C_j < size_of_matrix; C_j++)
                {
                    TransPlain[C_i, C_j] = inv_Plain[C_j, C_i];
                }
            }
            int[,] CT_matrix = new int[size_of_matrix, size_of_matrix];
            counters = 0;
            for (int C_i = 0; C_i < size_of_matrix; C_i++)
            {
                for (int C_j = 0; C_j < size_of_matrix; C_j++)
                {
                    CT_matrix[C_j, C_i] = cipher3[counters];
                    counters++;
                }
            }
            cipher3.Clear();
            for (int C_i = 0; C_i < size_of_matrix; C_i++)
            {
                for (int C_j = 0; C_j < size_of_matrix; C_j++)
                {
                    cipher3.Add(CT_matrix[C_i, C_j]);
                }
            }
            counters = 0;
            int res_of_multiply = 0;
            List<int> the_key = new List<int>();
            for (int C_i = 0; C_i < cipher3.Count; C_i += size_of_matrix)
            {
                for (int C_j = 0; C_j < size_of_matrix; C_j++)
                {
                    for (int c = 0; c < size_of_matrix; c++)
                    {
                        res_of_multiply += cipher3[counters] * TransPlain[c, C_j];
                        counters++;
                    }
                    if (res_of_multiply > 25)
                        res_of_multiply = res_of_multiply % 26;
                    counters -= 3;
                    the_key.Add(res_of_multiply);
                    res_of_multiply = 0;
                }
                counters += size_of_matrix;
            }
            return the_key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}