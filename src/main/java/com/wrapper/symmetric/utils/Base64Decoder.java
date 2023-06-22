package com.wrapper.symmetric.utils;

import java.util.Base64;

public class Base64Decoder {

    public static byte[] decodeBase64(byte[] input) { return Base64.getDecoder().decode(input); }

    public static byte[] decodeBase64(String input) {
        return Base64.getDecoder().decode(input);
    }
}
