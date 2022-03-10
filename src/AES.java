import java.math.*;
import java.util.stream.StreamSupport;

public class AES {
    public static int[][][] roundKey = new int[11][4][4];
    public static void main (String[] args) {

        long startTime1 = System.currentTimeMillis();    //获取开始时间

        String text = "00000000000000000000000000000000";
        String key = "00000000000000000000000000000000";
        for (int i=0;i<4000000;i++) {
            //System.out.println(encrypt(text, key));
            System.out.println(decrypt(text, key));
            text = ADD(text);
            key = ADD(key);
        }

        long endTime1 = System.currentTimeMillis();    //获取结束时间
        System.out.println("代码运行时间：" + (endTime1 - startTime1) + "ms");    //输出程序运行时间
    }

    //加密函数
    public static String encrypt (String plaintext, String key) {
        int i, j, k;
        int[][] state =  new int[4][4];
        generateKeys(key);
        plaintext = new BigInteger(plaintext, 16).toString(2);
        while (plaintext.length() < 128)
            plaintext = "0" + plaintext;

        for (i=0, k=0;i<4;i++){
            for (j=0;j<4;j++){
                state[i][j] = Integer.parseInt(plaintext.substring(k, k+8), 2);
                k += 8;
            }
        }

        state = addRoundKey(state, roundKey[0]);

        //9次运算四个基本运算都有
        for (i=1;i<10;i++)
            state = addRoundKey(mixColumn(shiftRow(ByteSub(state))), roundKey[i]);

        //最后一次没有列混淆
        state = addRoundKey(shiftRow(ByteSub(state)), roundKey[10]);

        //将最终结果转化为字符串
        String result = "";
        String tem;
        for (i=0;i<4;i++){
            for (j=0;j<4;j++){
                tem = Integer.toHexString(state[i][j]);
                while (tem.length() < 2)
                    tem = "0" + tem;
                result += tem;
            }
        }

        return result;
    }

    //以下为解密函数
    public static String decrypt (String ciphertext, String key) {
        int i, j, k;
        int[][] state = new int[4][4];
        generateKeys(key);
        ciphertext = new BigInteger(ciphertext, 16).toString(2);
        while (ciphertext.length() < 128)
            ciphertext = "0" + ciphertext;

        for (i=0, k=0;i<4;i++){
            for (j=0;j<4;j++){
                state[i][j] = Integer.parseInt(ciphertext.substring(k, k+8), 2);
                k += 8;
            }
        }

        state = addRoundKey(state, roundKey[10]);

        for (i=9;i>0;i--)
            state = invMixColumn(addRoundKey(invByteSub(invShiftRow(state)), roundKey[i]));

        //最后一次没有逆向列混淆
        state = addRoundKey(invByteSub(invShiftRow(state)), roundKey[0]);

        //将最终结果转化为字符串
        String result = "";
        String tem;
        for (i=0;i<4;i++){
            for (j=0;j<4;j++){
                tem = Integer.toHexString(state[i][j]);
                while (tem.length() < 2)
                    tem = "0" + tem;
                result += tem;
            }
        }

        return result;
    }

    public static void generateKeys (String key) {
        int i, j;

        //先将初始密钥转为二进制字符串
        key = new BigInteger(key, 16).toString(2);
        while (key.length() < 128)
            key = "0" + key;

        //先输入原始密钥
        for (i=0;i<4;i++) {
            for (j=0;j<4;j++){
                roundKey[0][i][j] = Integer.parseInt(key.substring((i*4+j)*8, (i*4+j)*8+8), 2);

            }
        }

        //进行密钥扩展
        for (i=1;i<11;i++){
            for (j=0;j<4;j++){
                if (j == 0){
                    roundKey[i][j] = XOR(roundKey[i-1][j], XOR(subWord(rotWord(roundKey[i-1][3])), Rcon[i-1]));
                }
                else
                    roundKey[i][j] = XOR(roundKey[i][j-1], roundKey[i-1][j]);
            }
        }
    }

    //以下函数实现密钥生成中的左移运算
    public static int[] rotWord (int[] b) {
        int[] result = new int[4];
        result[0] = b[1];
        result[1] = b[2];
        result[2] = b[3];
        result[3] = b[0];
        return result;
    }

    //以下函数实现密钥生成中的字节替换运算
    public static int[] subWord (int[] b) {
        int[] result = new int[4];
        for (int i=0;i<4;i++)
            result[i] = byteSub(b[i]);
        return result;
    }

    //以下函数实现加密函数中的字节替换运算
    public static int[][] ByteSub (int[][] state) {
        int[][] result =  new int[state.length][state[0].length];
        for (int i=0;i<state.length;i++) {
            for (int j=0;j<state[0].length;j++)
                result[i][j] = byteSub(state[i][j]);
        }
        return result;
    }

    //以下函数实现解密函数中的逆向字节替换运算
    public static int[][] invByteSub (int[][] afterShiftRow) {
        int[][] result = new int[afterShiftRow.length][afterShiftRow[0].length];
        for (int i=0;i<afterShiftRow.length;i++) {
            for (int j=0;j<afterShiftRow[0].length;j++)
                result[i][j] = invbytesub(afterShiftRow[i][j]);
        }
        return result;
    }

    //以下函数实现单个字节代替
    public static int byteSub (int a) {
        return Sbox[a>>4][a&0b00001111];
    }

    //以下函数实现单个逆字节代替
    public static int invbytesub (int a) {
        return inverseSbox[a>>4][a&0b00001111];
    }

    //以下函数实现加密中的行移位
    public static int[][] shiftRow (int[][] afterSub) {
        int[][] result = new int[4][4];
        result[0][0] = afterSub[0][0]; result[0][1] = afterSub[1][1]; result[0][2] = afterSub[2][2]; result[0][3] = afterSub[3][3];
        result[1][0] = afterSub[1][0]; result[1][1] = afterSub[2][1]; result[1][2] = afterSub[3][2]; result[1][3] = afterSub[0][3];
        result[2][0] = afterSub[2][0]; result[2][1] = afterSub[3][1]; result[2][2] = afterSub[0][2]; result[2][3] = afterSub[1][3];
        result[3][0] = afterSub[3][0]; result[3][1] = afterSub[0][1]; result[3][2] = afterSub[1][2]; result[3][3] = afterSub[2][3];
        return result;
    }

    //以下函数实现解密中的逆向行移位
    public static int[][] invShiftRow (int[][] state) {
        int[][] result = new int[4][4];
        result[0][0] = state[0][0]; result[0][1] = state[3][1]; result[0][2] = state[2][2]; result[0][3] = state[1][3];
        result[1][0] = state[1][0]; result[1][1] = state[0][1]; result[1][2] = state[3][2]; result[1][3] = state[2][3];
        result[2][0] = state[2][0]; result[2][1] = state[1][1]; result[2][2] = state[0][2]; result[2][3] = state[3][3];
        result[3][0] = state[3][0]; result[3][1] = state[2][1]; result[3][2] = state[1][2]; result[3][3] = state[0][3];
        return result;
    }

    //以下函数实现加密中的列混淆
    public static int[][] mixColumn (int[][] afterShiftRow) {
        int[][] result = new int[4][4];
        for (int i=0;i<4;i++){
            result[i][0] = multiply(0x2, afterShiftRow[i][0]) ^ multiply(0x3, afterShiftRow[i][1]) ^ afterShiftRow[i][2] ^ afterShiftRow[i][3];
            result[i][1] = afterShiftRow[i][0] ^ multiply(0x2, afterShiftRow[i][1]) ^ multiply(0x3, afterShiftRow[i][2]) ^ afterShiftRow[i][3];
            result[i][2] = afterShiftRow[i][0] ^ afterShiftRow[i][1] ^ multiply(0x2, afterShiftRow[i][2]) ^ multiply(0x3, afterShiftRow[i][3]);
            result[i][3] = multiply(0x3, afterShiftRow[i][0]) ^ afterShiftRow[i][1] ^ afterShiftRow[i][2] ^ multiply(0x2, afterShiftRow[i][3]);
        }
        return result;
    }

    //以下函数实现解密中的逆向列混淆
    public static int[][] invMixColumn (int[][] afterAddroundKey) {
        int[][] result = new int[4][4];
        for (int i=0;i<4;i++) {
            result[i][0] = multiply(0xe, afterAddroundKey[i][0]) ^ multiply(0xb, afterAddroundKey[i][1]) ^ multiply(0xd, afterAddroundKey[i][2]) ^ multiply(0x9, afterAddroundKey[i][3]);
            result[i][1] = multiply(0x9, afterAddroundKey[i][0]) ^ multiply(0xe, afterAddroundKey[i][1]) ^ multiply(0xb, afterAddroundKey[i][2]) ^ multiply(0xd, afterAddroundKey[i][3]);
            result[i][2] = multiply(0xd, afterAddroundKey[i][0]) ^ multiply(0x9, afterAddroundKey[i][1]) ^ multiply(0xe, afterAddroundKey[i][2]) ^ multiply(0xb, afterAddroundKey[i][3]);
            result[i][3] = multiply(0xb, afterAddroundKey[i][0]) ^ multiply(0xd, afterAddroundKey[i][1]) ^ multiply(0x9, afterAddroundKey[i][2]) ^ multiply(0xe, afterAddroundKey[i][3]);
        }
        return result;
    }

    //以下函数实现两个数组的按位异或运算
    public static int[] XOR (int[] a, int[] b) {
        if (a.length != b.length){
            System.out.println("XOR Failed!");
            return null;
        }

        int[] result = new int[a.length];

        for (int i=0;i<a.length;i++)
            result[i] = a[i]^b[i];
        return result;
    }

    //以下函数实现轮密钥加操作，本质是两个二维数组的异或运算
    public static int[][] addRoundKey (int[][] a, int[][] b) {
        if (a.length == b.length) {
            if (a[0].length == b[0].length) {
                int[][] result = new int[a.length][a[0].length];
                for (int i=0;i<a.length;i++){
                    for (int j=0;j<a[0].length;j++)
                        result[i][j] = a[i][j] ^ b[i][j];
                }
                return result;
            }
        }
        System.out.println("Add Round Key Failed!");
        return null;
    }

    //以下函数实现有限域上的乘法运算
    public static int multiply (int a, int b){
        int poly = 0b100011011;//以0x11b为不可约多项式
        int result = 0;

        while (b>0){
            if (b%2 == 1)
                result ^= a;
            a = gmul(a, poly);
            b >>= 1;
        }

        return result;
    }

    //以下函数计算有限域乘法的中间结果
    public static int gmul (int a, int p){
        a <<= 1;
        if ((a&0x100) == 0x100)
            a ^= p;
        return (a&0xff);
    }

    //以下函数实现明文与密钥+1的功能，按16进制处理
    public static String ADD (String COUNT) {
        String result = new BigInteger(COUNT, 16).add(BigInteger.ONE).toString(16);
        while (result.length() < 32)
            result = "0" + result;
        return result;
    }

    public static final int[][] Rcon = {
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00},
    };

    public static final int[][] Sbox = {
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
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    public static final int[][] inverseSbox = {
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
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
    };

}
