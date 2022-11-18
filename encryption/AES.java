package encryption;

import util.Util;

import java.nio.charset.StandardCharsets;

public class AES implements SymmetricalEncryption {
    private static final int Nr = 10;
    private int[] keys;

    public AES() {
        keys = new int[4 * (Nr + 1)];
    }


    private int[][] S_Box = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76     },
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
                    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
                    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
                    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
                    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
                    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
                    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
                    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
                    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
                    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
                    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
                    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
                    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
                    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
                    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
                    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    private int[][] Inv_S_Box = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
                    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
                    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
                    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
                    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
                    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
                    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
                    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
                    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
                    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
                    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
                    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
                    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
            {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
                    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
                    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
                    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };

    private int[] Rcon = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
            0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

    // 获取num中p位置上的二进制数
    private int getBit(int num, int p) {
        return (num >> p) & 1;
    }

    // 进行S盒替换，前四位表示行号，后四位表示列号
    private void subBytes(int[] mtx) {
        for (int i = 0; i < 16; ++i) {
            int row = getBit(mtx[i], 7) * 8 + getBit(mtx[i], 6) * 4 + getBit(mtx[i], 5) * 2 + getBit(mtx[i], 4);
            int column = getBit(mtx[i], 3) * 8 + getBit(mtx[i], 2) * 4 + getBit(mtx[i], 1) * 2 + getBit(mtx[i], 0);
            mtx[i] = S_Box[row][column];
        }
    }

    // 逆S盒替换
    private void invSubBytes(int[] mtx) {
        for (int i = 0; i < 16; ++i) {
            int row = getBit(mtx[i], 7) * 8 + getBit(mtx[i], 6) * 4 + getBit(mtx[i], 5) * 2 + getBit(mtx[i], 4);
            int column = getBit(mtx[i], 3) * 8 + getBit(mtx[i], 2) * 4 + getBit(mtx[i], 1) * 2 + getBit(mtx[i], 0);
            mtx[i] = Inv_S_Box[row][column];
        }
    }

    // 行变换
    private void shiftRows(int[] mtx) {
        // 第二行左移一位
        int tmp = mtx[4];
        for (int i = 4; i < 7; ++i) {
            mtx[i] = mtx[i + 1];
        }
        mtx[7] = tmp;
        // 第三行左移两位
        for (int i = 8; i < 10; ++i) {
            tmp = mtx[i];
            mtx[i] = mtx[i + 2];
            mtx[i + 2] = tmp;
        }
        tmp = mtx[15];
        // 第四行左移三位
        for (int i = 15; i > 12; --i) {
            mtx[i] = mtx[i - 1];
        }
        mtx[12] = tmp;
    }

    // 逆行变换
    private void invShiftRows(int[] mtx) {
        // 第二行右移一位
        int tmp = mtx[7];
        for (int i = 7; i > 4; --i) {
            mtx[i] = mtx[i - 1];
        }
        mtx[4] = tmp;
        // 第三行右移两位
        for (int i = 8; i < 10; ++i) {
            tmp = mtx[i];
            mtx[i] = mtx[i + 2];
            mtx[i + 2] = tmp;
        }
        tmp = mtx[12];
        // 第四行右移三位
        for (int i = 12; i < 15; ++i) {
            mtx[i] = mtx[i + 1];
        }
        mtx[15] = tmp;
    }

    // 列变换
    private void mixColumns(int[] mtx) {
        int[] tmp = new int[4];
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                tmp[j] = mtx[i + 4 * j];
            }
            mtx[i] = GFMul(0x02, tmp[0]) ^ GFMul(0x03, tmp[1]) ^ tmp[2] ^ tmp[3];
            mtx[i + 4] = tmp[0] ^ GFMul(0x02, tmp[1]) ^ GFMul(0x03, tmp[2]) ^ tmp[3];
            mtx[i + 8] = tmp[0] ^ tmp[1] ^ GFMul(0x02, tmp[2]) ^ GFMul(0x03, tmp[3]);
            mtx[i + 12] = GFMul(0x03, tmp[0]) ^ tmp[1] ^ tmp[2] ^ GFMul(0x02, tmp[3]);
        }
    }

    private void invMixColumns(int[] mtx) {
        int[] tmp = new int[4];
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                tmp[j] = mtx[i + 4 * j];
            }
            mtx[i] = GFMul(0x0e, tmp[0]) ^ GFMul(0x0b, tmp[1]) ^ GFMul(0x0d, tmp[2]) ^ GFMul(0x09, tmp[3]);
            mtx[i + 4] = GFMul(0x09, tmp[0]) ^ GFMul(0x0e, tmp[1]) ^ GFMul(0x0b, tmp[2]) ^ GFMul(0x0d, tmp[3]);
            mtx[i + 8] = GFMul(0x0d, tmp[0]) ^ GFMul(0x09, tmp[1]) ^ GFMul(0x0e, tmp[2]) ^ GFMul(0x0b, tmp[3]);
            mtx[i + 12] = GFMul(0x0b, tmp[0]) ^ GFMul(0x0d, tmp[1]) ^ GFMul(0x09, tmp[2]) ^ GFMul(0x0e, tmp[3]);
        }
    }

    // 将每一列与密钥进行异或
    private void addRoundKey(int[] mtx, int[] k) {
        for (int i = 0; i < 4; ++i) {
            int k1 = k[i] >>> 24;
            int k2 = k[i] << 8 >>> 24;
            int k3 = k[i] << 16 >>> 24;
            int k4 = k[i] << 24 >>> 24;
            mtx[i] = mtx[i] ^ k1;
            mtx[i + 4] = mtx[i + 4] ^ k2;
            mtx[i + 8] = mtx[i + 8] ^ k3;
            mtx[i + 12] = mtx[i + 12] ^ k4;
        }
    }

    // 有限域上的乘法
    private int GFMul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; ++i) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            int h = a & 0x80;
            a <<= 1;
            if (h != 0) {
                a ^= 0x1b;
            }
            b >>>= 1;
        }
        return p;
    }

    // 将4个字节拼接成一个整数
    private int byteToWord(int b1, int b2, int b3, int b4) {
        return ((b1 & 0xff) << 24) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 8) | (b4 & 0xff);
    }

    // 将一个字循环左移一个字节
    private int rotWord(int w) {
        int high = w << 8;
        int low = w >>> 24;
        return high | low;
    }

    // 将一个字中的每一个字节都进行S盒替换
    private int subWord(int w) {
        int r = 0;
        for (int i = 0; i < 32; i += 8) {
            int row = getBit(w, i + 7) * 8 + getBit(w, i + 6) * 4 + getBit(w, i + 5) * 2 + getBit(w, i + 4);
            int column = getBit(w, i + 3) * 8 + getBit(w, i + 2) * 4 + getBit(w, i + 1) * 2 + getBit(w, i);
            int val = S_Box[row][column];
            r |= (val << i);
        }
        return r;
    }

    // 生成密钥
    @Override
    public void setKey(byte[] key) {
        int[] new_key = new int[16];
        int i = 0;
        while (i < 16) {
            if (i == key.length) {
                break;
            }
            new_key[i] = key[i];
            ++i;
        }
        while (i < 16) {
            new_key[i++] = 0;
        }
        i = 0;
        int tmp;
        while (i < 4) {
            keys[i] = byteToWord(new_key[4 * i], new_key[4 * i + 1], new_key[4 * i + 2], new_key[4 * i + 3]);
            ++i;
        }
        while (i < 4 * (Nr + 1)) {
            tmp = keys[i - 1];
            if (i % 4 == 0) {
                keys[i] = keys[i - 4] ^ subWord(rotWord(tmp)) ^ Rcon[i / 4 - 1];
            } else {
                keys[i] = keys[i - 4] ^ tmp;
            }
            ++i;
        }
    }

    private void encryptionHelper(int[] data) {
        int[] k = new int[4];
        for (int i = 0; i < 4; ++i) {
            k[i] = keys[i];
        }
        addRoundKey(data, k);
        for (int i = 1; i < Nr; ++i) {
            subBytes(data);
            shiftRows(data);
            mixColumns(data);
            for (int j = 0; j < 4; ++j) {
                k[j] = keys[i * 4 + j];
            }
            addRoundKey(data, k);
        }
        subBytes(data);
        shiftRows(data);
        for (int j = 0; j < 4; ++j) {
            k[j] = keys[Nr * 4 + j];
        }
        addRoundKey(data, k);
    }

    private void decryptionHelper(int[] data) {
        int[] k = new int[4];
        for (int i = 0; i < 4; ++i) {
            k[i] = keys[4 * Nr + i];
        }
        addRoundKey(data, k);
        for (int i = Nr - 1; i > 0; --i) {
            invShiftRows(data);
            invSubBytes(data);
            for (int j = 0; j < 4; ++j) {
                k[j] = keys[i * 4 + j];
            }
            addRoundKey(data, k);
            invMixColumns(data);
        }
        invShiftRows(data);
        invSubBytes(data);
        for (int j = 0; j < 4; ++j) {
            k[j] = keys[j];
        }
        addRoundKey(data, k);
    }


    // 加密
    @Override
    public byte[] encryption(byte[] data) {
        long begin = System.nanoTime();
        int n = data.length;
        if (n % 16 != 0) {
            n = 16 * (n / 16 + 1);
        }
        byte[] new_data = new byte[n];
        int[] tmp = new int[16];
        int i = 0;
        while (i < data.length) {
            new_data[i] = data[i];
            ++i;
        }
        while (i < n) {
            new_data[i] = 0;
            ++i;
        }
        for (i = 0; i < n; i += 16) {
            for (int j = 0; j < 16; ++j) {
                tmp[j] = new_data[i + j];
            }
            encryptionHelper(tmp);
            for (int j = 0; j < 16; ++j) {
                new_data[i + j] = (byte) tmp[j];
            }
        }
        long end = System.nanoTime();
        Util.TIME = end - begin;
        return new_data;
    }


    // 解密
    @Override
    public byte[] decryption(byte[] data) {
        long begin = System.nanoTime();
        int[] tmp = new int[16];
        for (int i = 0; i < data.length; i += 16) {
            for (int j = 0; j < 16; ++j) {
                tmp[j] = data[i + j];
            }
            decryptionHelper(tmp);
            for (int j = 0; j < 16; ++j) {
                data[i + j] = (byte) tmp[j];
            }
        }
        long end = System.nanoTime();
        Util.TIME = end - begin;
        return data;
    }


    public static void main(String[] args) {
        String key = "jasdbjabsd";
        String data = "dnajnd621357sdhddfs,aokrew";
        AES aes = new AES();
        aes.setKey(key.getBytes(StandardCharsets.UTF_8));
        byte[] data_b = data.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < data_b.length; ++i) {
            System.out.printf(data_b[i] + " ");
        }
        System.out.println();
        byte[] encry = aes.encryption(data_b);
        for (int i = 0; i < encry.length; ++i) {
            System.out.printf(encry[i] + " ");
        }
        System.out.println();
        byte[] decry = aes.decryption(encry);
        for (int i = 0; i < decry.length; ++i) {
            System.out.printf(decry[i] + " ");
        }
        System.out.println();
        System.out.println(new String(decry));

    }
}
