package util;

import encryption.AES;
import encryption.SymmetricalEncryption;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Util {
    public static long TIME;

    private static byte hexToByte(String inHex) {
        return (byte) Integer.parseInt(inHex, 16);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            String hex = Integer.toHexString(aByte & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    public static byte[] hexToByteArray(String inHex) {
        int hexlen = inHex.length();
        byte[] result;
        if (hexlen % 2 == 1) {
            //奇数
            hexlen++;
            result = new byte[(hexlen / 2)];
            inHex = "0" + inHex;
        } else {
            //偶数
            result = new byte[(hexlen / 2)];
        }
        int j = 0;
        for (int i = 0; i < hexlen; i += 2) {
            result[j] = hexToByte(inHex.substring(i, i + 2));
            j++;
        }
        return result;
    }

    private static byte[] read(String fileName) {
        File file = new File(fileName);
        List<Byte> list = new ArrayList<>();
        if (file.isFile()) {
            // 以字节流方法读取文件
            FileInputStream fis;
            try {
                fis = new FileInputStream(file);
                // 设置一个，每次 装载信息的容器
                byte[] buf = new byte[1024];
                // 定义一个StringBuffer用来存放字符串
                StringBuilder sb = new StringBuilder();
                // 开始读取数据
                int len = 0;// 每次读取到的数据的长度
                while ((len = fis.read(buf)) != -1) {// len值为-1时，表示没有数据了
                    // append方法往sb对象里面添加数据
                    for (int i = 0; i < len; ++i) {
                        list.add(buf[i]);
                    }
                }
                byte[] bytes = new byte[list.size()];
                for (int i = 0; i < list.size(); ++i) {
                    bytes[i] = list.get(i);
                }
                return bytes;
                // 输出字符串
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("file does not exist");
        }
        return null;
    }

    private static void write(String fileName, byte[] content) {
        File file = new File(fileName);
        if (file.exists()) {
            file.delete();
        }
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(content, 0, content.length);
            fos.flush();
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void fileEncry(String fileName, String key, SymmetricalEncryption c) {
        byte[] data = read(fileName);
        c.setKey(key.getBytes(StandardCharsets.UTF_8));
        byte[] b = c.encryption(data);
        int i = fileName.length() - 1;
        for (; i >= 0; --i) {
            if (fileName.charAt(i) == '.') {
                break;
            }
        }
        StringBuilder builder = new StringBuilder();
        builder.append(fileName, 0, i);
        builder.append("_encry");
        if (c instanceof AES) {
            builder.append("_aes");
        } else {
            builder.append("_des");
        }
        builder.append(fileName.substring(i));
        write(builder.toString(), b);
    }

    public static void fileDecry(String fileName, String key, SymmetricalEncryption c) {
        byte[] data = read(fileName);
        c.setKey(key.getBytes(StandardCharsets.UTF_8));
        byte[] b = c.decryption(data);
        int i = fileName.length() - 1;
        for (; i >= 0; --i) {
            if (fileName.charAt(i) == '.') {
                break;
            }
        }
        StringBuilder builder = new StringBuilder();
        builder.append(fileName, 0, i);
        builder.append("_decry");
        if (c instanceof AES) {
            builder.append("_aes");
        } else {
            builder.append("_des");
        }
        builder.append(fileName.substring(i));
        write(builder.toString(), b);
    }
}


