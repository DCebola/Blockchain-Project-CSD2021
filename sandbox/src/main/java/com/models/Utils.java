package com.models;

public class Utils {
    private static final String digits = "0123456789abcdef";

    private static String toHex(byte[] data, int length) {

        StringBuffer buf = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Retorna dados passados como byte array numa string hexadecimal
     *
     * @param data : bytes a serem convertidos
     * @return : representacao hexadecimal dos dados.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static byte[] toByteArray(
            String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    /**
     * Returns the n leftmost significant bytes from a an array of bytes as a String.
     *
     * @param data : bytes from where the most significant bytes will be extracted
     * @param n : the number of leftmost significant bytes to extract.
     * @return : n leftmost significant bytes from a an array of bytes as a String.
     */
    public static String getMostSignificantBytes(int n, byte[] data) {
        String mostSignificantBytes = "";
        for (int i = 0; i < n; i++)
            mostSignificantBytes = mostSignificantBytes.concat(Integer.toBinaryString(data[i] & 255 | 256).substring(1));
        return mostSignificantBytes;

    }
}
