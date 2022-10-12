using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {
        public Byte R(int a, int i, int j, byte[,] state)
        {
            switch (a)
            {
                case 1:
                    byte[,] inverseSbox = new byte[16, 16] {
      {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
      {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
      {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
      {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
      {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
      {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
      {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
      {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
      {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
      {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
      {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
      {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
      {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
      {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
      {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
      {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };
                    return inverseSbox[state[i, j] >> 4, state[i, j] & 0x0f];
                case 2:
                    byte[,] Rcon = new byte[4, 10] {
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
                    return Rcon[i, j - 1];
                default:

                    break;
            }
            return 0;
        }
        public byte[,] h(int c, byte[,] s, int r)
        {
            switch (c)
            {
                case 1:
                    // Function InverseMixColumns
                    byte[,] inversemix = new byte[4, 4] {
                {0X0E,0X0B, 0X0D,0X09},
                { 0X09,0X0E,0X0B,0X0D},
                { 0X0D,0X09,0X0E,0X0B},
                { 0X0B,0X0D,0X09,0X0E}
                };
                    byte[,] b = new byte[4, 4];
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            byte R = 0x00;

                            for (int q = 0; q < 4; q++)
                            {
                                byte tmp = 0x00;
                                byte[] bt = new byte[8];
                                bt = muliply(s[q, j]);
                                byte t = inversemix[i, q];
                                BitArray bitarray = new BitArray(BitConverter.GetBytes(t).ToArray());

                                for (int k = 0; k < 8; k++)
                                {
                                    if (bitarray[k])
                                    {
                                        tmp = (byte)((int)tmp ^ (int)bt[k]);
                                    }
                                }
                                R = (byte)((int)R ^ (int)tmp);

                            }
                            b[i, j] = R;
                        }
                    }
                    return b;
                case 2:
                    // Function inverseShiftRows -1 in column(1 cell out of their index)
                    Swap(ref s[1, 2], ref s[1, 3]);
                    Swap(ref s[1, 1], ref s[1, 2]);
                    Swap(ref s[1, 0], ref s[1, 1]);
                    //
                    //-2 in column (2 cells out of their index)
                    Swap(ref s[2, 0], ref s[2, 2]);
                    Swap(ref s[2, 1], ref s[2, 3]);

                    //-1 in column (1 cell out of their index)
                    Swap(ref s[3, 0], ref s[3, 1]);
                    Swap(ref s[3, 1], ref s[3, 2]);
                    Swap(ref s[3, 2], ref s[3, 3]);
                    return s;
                case 3:
                    // Function inverseSubByte
                    byte[,] bytes2 = new byte[4, 4];
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            bytes2[i, j] = R(1, i, j, s);
                        }
                    }
                    return bytes2;
                case 4:
                    //Function bringKey
                    byte[,] bytes3 = new byte[4, 4];
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            bytes3[i, j] = bks[r, i, j];
                        }
                    }
                    return bytes3;
                default:
                    break;
            }
            return null;
        }
        byte[,] SBox = new byte[16, 16] {
      {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
      {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
      {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
      {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
      {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
      {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
      {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
      {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
      {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
      {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
      {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
      {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
      {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
      {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
      {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };
        // given matrix 34an tdrbha fe kol col mn al shifted col aly tl3t f round2
        byte[,] M = new byte[4, 4] {
        {0x02,0x03,0x01,0x01},
        {0x01,0x02,0x03,0x01},
        {0x01,0x01,0x02,0x03},
        {0x03,0x01,0x01,0x02}};
        static void Swap<T>(ref T lhs, ref T rhs)
        {
            T s;
            s = lhs;
            lhs = rhs;
            rhs = s;
        }

        static byte[] muliply(byte element)
        {
            byte[] bytearray = new byte[8];
            bytearray[0] = element;
            bytearray[1] = element >= 128 ? byte.Parse(((byte)(element << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(element << 1)).ToString());
            bytearray[2] = bytearray[1] >= 128 ? byte.Parse(((byte)(bytearray[1] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(bytearray[1] << 1)).ToString());
            bytearray[3] = bytearray[2] >= 128 ? byte.Parse(((byte)(bytearray[2] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(bytearray[2] << 1)).ToString());
            bytearray[4] = bytearray[3] >= 128 ? byte.Parse(((byte)(bytearray[3] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(bytearray[3] << 1)).ToString());
            bytearray[5] = bytearray[4] >= 128 ? byte.Parse(((byte)(bytearray[4] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(bytearray[4] << 1)).ToString());
            bytearray[6] = bytearray[5] >= 128 ? byte.Parse(((byte)(bytearray[5] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(bytearray[5] << 1)).ToString());
            bytearray[7] = bytearray[6] >= 128 ? byte.Parse(((byte)(bytearray[6] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(bytearray[6] << 1)).ToString());
            //   b[7] = b[6] >= 128 ? byte.Parse(((byte)(b[6] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(b[6] << 1)).ToString());

            // Console.WriteLine("Hex1: {0:X}", b[0]);
            // Console.WriteLine("Hex2: {0:X}", b[1]);
            // Console.WriteLine("Hex3: {0:X}", b[2]);
            // Console.WriteLine("Hex4: {0:X}", b[3]);
            // Console.WriteLine("Hex5: {0:X}", b[4]);
            // Console.WriteLine("Hex6: {0:X}", b[5]);
            // Console.WriteLine("Hex7: {0:X}", b[6]);
            // Console.WriteLine("Hex8: {0:X}", b[7]);
            return bytearray;
        }

        byte[,,] bks = new byte[10, 4, 4];
        public override string Decrypt(string ciphertext, string key)
        {
            byte[,] b_CT = StringToMatrixOfBytes(ciphertext);
            byte[,] bK = StringToMatrixOfBytes(key);
            for (int i = 0; i < 10; ++i)//10 rounds
            {
                for (int j = 0; j < 4; ++j)//size of plain text
                {
                    for (int q = 0; q < 4; ++q)
                    {
                        bks[i, q, j] = bK[q, j];//bkeys carry PT lsa hmlaha bl round
                    }
                }
                bK = GenerateRoundKey(bK, i + 1);//generate key to next round

            }
            // bKey = bringKey(10);
            b_CT = AddRoundkey(b_CT, bK);

            //Rounds 1 to 9
            for (int i = 9; i >= 1; --i)
            {
                bK = h(4, bK, i);
                b_CT = h(1, (AddRoundkey(h(3, (h(2, (b_CT), 0)), 0), bK)), 0);
            }
            //Round 10
            bK = h(4, bK, 0);
            b_CT = AddRoundkey(h(3, (h(2, (b_CT), 0)), 0), bK);

            return MatrixOfBytesToString(b_CT);

        }
        public override string Encrypt(string plainText, string key)
        {
            byte[,] b_PT = StringToMatrixOfBytes(plainText);
            byte[,] bK = StringToMatrixOfBytes(key);
            //Round 0
            b_PT = AddRoundkey(b_PT, bK);
            //Rounds 1 to 9
            for (int i = 1; i <= 9; i++)
            {
                bK = GenerateRoundKey(bK, i);
                b_PT = AddRoundkey(MixColumns(ShiftRows(SubBytes(b_PT))), bK);
            }
            //Round 10 without mix col
            bK = GenerateRoundKey(bK, 10);
            b_PT = AddRoundkey(ShiftRows(SubBytes(b_PT)), bK);

            return MatrixOfBytesToString(b_PT);
        }
        private byte[,] MixColumns(byte[,] b_PT)
        {
            byte[,] b = new byte[4, 4];
            int num = 4;
            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < num; j++)
                {
                    byte r = 0x00;
                    for (int q = 0; q < num; q++)
                    {
                        byte t;
                        if (M[i, q] == 0x03)
                        {//sub diagonal
                            t = (byte)(b_PT[q, j] << 1);//shift 
                            if ((byte)(b_PT[q, j] & 0x80) == 0x80)//lma bywsl LL a5r ylf w yrg3 tany
                            {
                                //followed by XOR, when reach 11111, do xor with 1b to avod 1 loss
                                t = (byte)((int)t ^ (int)(0x1b));//to begin from first
                            }
                            t = (byte)((int)t ^ (int)b_PT[q, j]);
                        }
                        else if (M[i, q] == 0x02)
                        {//diagonal
                            t = (byte)(b_PT[q, j] << 1);
                            if ((byte)(b_PT[q, j] & 0x80) == 0x80)
                            {
                                t = (byte)((int)t ^ (int)(0x1b));
                            }
                        }
                        else
                        {
                            t = b_PT[q, j];
                        }
                        r = (byte)((int)r ^ (int)t);
                    }
                    b[i, j] = r;
                }
            }
            return b;
        }
        private byte[,] ShiftRows(byte[,] b_PT) //bn3ml shift 3la 7sb al index bta3t alrow
                                                // awl row mfesh shift 
                                                //tany row shift 1
                                                //and so on..
        {
            byte[,] b = new byte[4, 4];
            int num = 4;
            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < num; j++)
                {
                    if (j + i < 4)
                        b[i, j] = b_PT[i, j + i];
                    else
                        b[i, j] = b_PT[i, (j + i) - 4];//reach last return from begining
                }
            }
            return b;
        }
        private byte[,] SubBytes(byte[,] b_PT) //get the intersection of index by index in P.T from s-box after diviing it into 2 numbers
                                               // ie: 19=  1    9
                                               //in s box 1 from row and 9 from col

        //0x01 0x09 
        //0001 1001
        //0000 1111
        //9
        {
            byte[,] b = new byte[4, 4];
            int num = 4;//
            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < num; j++)
                {
                    b[i, j] = SBox[b_PT[i, j] >> 4/*get the first number by shift*/, b_PT[i, j] & 0x0f];/*get the second number by anding with f to stay same*/
                }
            }
            return b;
        }
        private byte[,] GenerateRoundKey(byte[,] bK, int r)
        {
            byte[,] b = new byte[4, 4];
            //hna sh2lb awl cell m3 a5r cell. w 3ml subistute mn al sbox
            //shift down
            b[0, 0] = SBox[bK[1, 3] >> 4, bK[1, 3] & 0x0f];
            b[1, 0] = SBox[bK[2, 3] >> 4, bK[2, 3] & 0x0f];
            b[2, 0] = SBox[bK[3, 3] >> 4, bK[3, 3] & 0x0f];
            b[3, 0] = SBox[bK[0, 3] >> 4, bK[0, 3] & 0x0f];
            //XOR 
            //get the first col 
            for (int i = 0; i < 4; i++)
            {
                b[i, 0] = (byte)((int)b[i, 0] ^ (int)R(2, i, r, null));
                b[i, 0] = (byte)((int)b[i, 0] ^ (int)bK[i, 0]);
            }

            for (int i = 1; i < 4; i++)//3yz ygeb tany col romady
                                       //bya5od aly ablo XOR m3 col 1 (tany col) 
            {
                for (int j = 0; j < 4; j++)
                    b[j, i] = (byte)((int)b[j, i - 1] ^ (int)bK[j, i]);
            }
            return b;
        }
        private byte[,] AddRoundkey(byte[,] bplainText, byte[,] bKey)
        {
            //take the output from mix colmn (prevois phase) and make XOR with L key bta3 L round dy
            byte[,] bytes = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    bytes[j, i] = (byte)((int)bplainText[j, i] ^ (int)bKey[j, i]);
                }
            }
            return bytes;
        }
        private byte[,] StringToMatrixOfBytes(string HexStr)
        {//functin to generate bkey (key bta3t al round aly ana feha)
            string s = HexStr.Substring(2, HexStr.Length - 2);//-2characters
            byte[] T = Enumerable.Range(0, s.Length) 
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
                             .ToArray();
            byte[,] b = new byte[4, 4];
            int count = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    b[j, i] = T[count];//convert 1d to 2d array
                    count++;
                }
            }
            return b;
        }
        private string MatrixOfBytesToString(byte[,] Mbytes)
        {
            byte[] bt = new byte[16];
            int count = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    bt[count] = Mbytes[j, i];//convert 2D to 1D
                    count++;//next cell (2)
                }
            }
            StringBuilder hex = new StringBuilder(bt.Length * 2) ;//bytb3tlo length of 1D multibly by 2 because each cell has 2 chars 
            foreach (byte b in bt)//fill al hexa bl 7roof 
                hex.AppendFormat("{0:x2}", b);// bt7ot kol 7rfen wra b3d 
            return "0x" + hex.ToString();
        }
    }
}


