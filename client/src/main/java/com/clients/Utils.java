package com.clients;

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
}
