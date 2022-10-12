using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        public int[] EE =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11,12, 13,
            12, 13, 14, 15, 16,17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };
        //last permutation
        public static int[] IPINV =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        public int[] PPC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        public int[] pcc2 =
        {   14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        public int[] permutation_in_last_mangular =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };
        public static int[] theIP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };


        public byte[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };
        private int[] _4ft_amount = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        //by7wl el hex string to bit array

        //-------------------------------------------Decreption---------------------------------------------
        public override string Decrypt(string cipherText, string key)
        {
            BitArray KeyN, PT_N, New_PT, Permution_arr, arr_shift_ed;
            KeyN = To_Bits_Conversion_from_hexString(key);
            PT_N = To_Bits_Conversion_from_hexString(cipherText);
            New_PT = theInitial_permution(PT_N);
            for (int C_ii = 15; C_ii >= 0; C_ii--)
            {
                arr_shift_ed = fn_applying_first_permution(KeyN);
                for (int j = 0; j <= C_ii; j++)
                {
                    arr_shift_ed = _4ft_left(arr_shift_ed, j);
                }
                Permution_arr = fn_applying_second_permution(arr_shift_ed);
                New_PT = generate_Rn_Ln(New_PT, Permution_arr);
            }
            New_PT = swab_bits(New_PT);
            New_PT = _inv_Permutation(New_PT);
            return HEx_conversion_fromBitArr(New_PT);
        }
        //-------------------------------------------Encreption---------------------------------------------
        public override string Encrypt(string plainText, string key)
        {
            BitArray Key_NN, PT_N, NewPT, ArrPermution, Arr_Shifted;
            Key_NN = To_Bits_Conversion_from_hexString(key);
            PT_N = To_Bits_Conversion_from_hexString(plainText);
            NewPT = theInitial_permution(PT_N);
            Arr_Shifted = fn_applying_first_permution(Key_NN);
            for (int C_ii = 0; C_ii <= 15; ++C_ii)
            {
                Arr_Shifted = _4ft_left(Arr_Shifted, C_ii);
                ArrPermution = fn_applying_second_permution(Arr_Shifted);
                NewPT = generate_Rn_Ln(NewPT, ArrPermution);
            }
            NewPT = swab_bits(NewPT);
            NewPT = _inv_Permutation(NewPT);
            return HEx_conversion_fromBitArr(NewPT);
        }
        public static BitArray To_Bits_Conversion_from_hexString(string strinG)
        {
            int L = strinG.Length;
            string hx_str = strinG.Substring(2, L - 2);
            int L2 = hx_str.Length;
            BitArray Bitss = new BitArray(L2 * 4);
            for (int C_ii = 0; C_ii < hx_str.Length; C_ii++)
            {
                byte Byte = byte.Parse(hx_str[C_ii].ToString(), NumberStyles.HexNumber);
                for (int JJ = 0; JJ < 4; JJ++)
                    Bitss.Set(C_ii * 4 + JJ, (Byte & (1 << (3 - JJ))) != 0);
            }
            return Bitss;
        }
        //convert key to 56 bits
        private BitArray fn_applying_first_permution(BitArray the_keyy)
        {
            BitArray carry_key_N = new BitArray(56);
            for (int C_ii = 0; C_ii < 56; ++C_ii)
                carry_key_N[C_ii] = the_keyy[PPC1[C_ii] - 1];
            return carry_key_N;
        }
        //create c and d by shiftting by matrix _4ft_amount
        private BitArray _4ft_left(BitArray the_bits, int theround)
        {
            int twenty8 = 28;
            BitArray right_side = new BitArray(twenty8);
            BitArray left_side = new BitArray(twenty8);
            int C_i;
            for (C_i = 0; C_i < twenty8; ++C_i)
            {
                left_side[C_i] = the_bits[C_i];
                right_side[C_i] = the_bits[C_i + twenty8];
            }

            int value_amount_value = _4ft_amount[theround];
            //hna bygeeb el c w el d bta3t el right w el left mn c1,d1 ---> c16,d16
            int c = left_side.Length, d = right_side.Length;
            BitArray c_left = new BitArray(c);

            BitArray d_right = new BitArray(d);
            int L3 = left_side.Length;
            for (int C_j = 0; C_j < L3; C_j++)
            {
                if (c > C_j + value_amount_value)
                {
                    c_left[C_j] = left_side[C_j + value_amount_value];
                    d_right[C_j] = right_side[C_j + value_amount_value];
                }
                else
                {
                    c_left[C_j] = left_side[(C_j + value_amount_value) - c];
                    d_right[C_j] = right_side[(C_j + value_amount_value) - d];
                }
            }
            BitArray c_and_d = new BitArray(56);
            for (int C_ii = 0; C_ii < twenty8; ++C_ii)
                c_and_d[C_ii] = c_left[C_ii];
            for (int C_jj = 0; C_jj < twenty8; ++C_jj)
                c_and_d[C_jj + twenty8] = d_right[C_jj];
            return c_and_d;
        }
        //convert after generate c and d to 48 bit
        private BitArray fn_applying_second_permution(BitArray thee_key)
        {
            BitArray NK2 = new BitArray(48);
            for (int C_ii = 0; C_ii < 48; ++C_ii)
                NK2[C_ii] = thee_key[pcc2[C_ii] - 1];
            return NK2;
        }
        //awl permutation bn3mloo ll message aly gaya lya b3d ma ngeeb el 16 key by ip matrix
        private BitArray theInitial_permution(BitArray PT_new)
        {
            BitArray BitarrN_R;
            BitarrN_R = new BitArray(64);
            for (int C_i = 0; C_i < 64; ++C_i)
                BitarrN_R[C_i] = PT_new[theIP[C_i] - 1];
            return BitarrN_R;
        }
        //to get r16 and l16
        private BitArray generate_Rn_Ln(BitArray PT_round, BitArray key_round)
        {
            BitArray rn, left, ln, right;
            rn = new BitArray(32);
            left = new BitArray(32);
            ln = new BitArray(32);
            right = new BitArray(32);
            for (int C_i = 0; C_i < 32; ++C_i)
            {
                left[C_i] = PT_round[C_i];
                right[C_i] = PT_round[C_i + 32];
            }
            ln = right;
            BitArray bitArr2 = new BitArray(48);
            bitArr2 = ExpantionFn_appling(right);
            bitArr2.Xor(key_round);
            rn = S_box(bitArr2);
            rn = permution_fn_applying(rn);
            rn.Xor(left);
            BitArray PT_I = new BitArray(64);
            for (int C_ii = 0; C_ii < 32; ++C_ii)
                PT_I[C_ii] = ln[C_ii];
            for (int C_II = 0; C_II < 32; ++C_II)
                PT_I[C_II + 32] = rn[C_II];
            return PT_I;
        }
        // expantion ely bn3mlo 3lshan n7wl el left ely 32 bit hn7too fe el right l 48 bit
        private BitArray ExpantionFn_appling(BitArray R)
        {
            BitArray ArrNR = new BitArray(48);
            for (int C_ii = 0; C_ii < 48; ++C_ii)
                ArrNR[C_ii] = R[EE[C_ii] - 1];
            return ArrNR;
        }
        //convert 45 bit to 32 bit by s_box matrix
        private BitArray S_box(BitArray bitarr_ArrR)
        {
            BitArray row = new BitArray(2);
            BitArray column = new BitArray(4);
            BitArray theNewR = new BitArray(32);
            int C_i = 0;
            for (int C_ii = 0; C_ii < 48; C_ii += 6)
            {
                row[0] = bitarr_ArrR[C_ii + 5];
                row[1] = bitarr_ArrR[C_ii];                      //011000   //row=00 //column=1100  
                int[] INt = new int[1];
                row.CopyTo(INt, 0);
                column[0] = bitarr_ArrR[C_ii + 4];
                column[1] = bitarr_ArrR[C_ii + 3];
                column[2] = bitarr_ArrR[C_ii + 2];
                column[3] = bitarr_ArrR[C_ii + 1];
                int[] INT2 = new int[1];
                column.CopyTo(INT2, 0);
                byte u = SBoxes[C_ii / 6, INt[0] * 16 + INT2[0]];
                BitArray Byttes = new BitArray(BitConverter.GetBytes(u).ToArray());//bits
                for (int j = 0; j < 4; ++j)
                {
                    theNewR[C_i] = Byttes[3 - j];
                    C_i++;
                }
            }
            return theNewR;
        }

        //a5r permutation bn3mloo ll right1 
        private BitArray permution_fn_applying(BitArray R)
        {
            BitArray arrNP = new BitArray(32);
            for (int C_ii = 0; C_ii < 32; ++C_ii)
                arrNP[C_ii] = R[permutation_in_last_mangular[C_ii] - 1];
            return arrNP;
        }
        // b3d ma bwsl ll r16 and l16 b swap w b3d kda bgm3hm fe newpt 3lshan yb2a 64 bit
        private BitArray swab_bits(BitArray NewPt)
        {
            BitArray left;
            BitArray Right;
            left = new BitArray(32);
            Right = new BitArray(32);
            for (int C_i = 0; C_i < 32; ++C_i)
            {
                left[C_i] = NewPt[C_i];
                Right[C_i] = NewPt[C_i + 32];
            }
            for (int C_i = 0; C_i < 32; ++C_i)
            {
                NewPt[C_i] = Right[C_i];
                NewPt[C_i + 32] = left[C_i];
            }
            return NewPt;
        }
        //last permutation to my plain text by ip inv matrix 
        private BitArray _inv_Permutation(BitArray NewPT)
        {
            BitArray Bitarr_NR;
            Bitarr_NR = new BitArray(64);
            for (int C_ii = 0; C_ii < 64; ++C_ii)
                Bitarr_NR[C_ii] = NewPT[IPINV[C_ii] - 1];
            return Bitarr_NR;
        }
        //the last edit bn7wl el bit array to hex 
        private string HEx_conversion_fromBitArr(BitArray Arr_bits)
        {
            StringBuilder Build_S;
            int L = Arr_bits.Length / 4;
            int L2 = Arr_bits.Length;
            Build_S = new StringBuilder(L);
            for (int i = 0; i < L2; i += 4)
            {
                int Value = (Arr_bits[i] ? 8 : 0) | (Arr_bits[i + 1] ? 4 : 0) | (Arr_bits[i + 2] ? 2 : 0) | (Arr_bits[i + 3] ? 1 : 0);

                Build_S.Append(Value.ToString("x1"));
            }
            return "0x" + Build_S.ToString();
        }
    }
}