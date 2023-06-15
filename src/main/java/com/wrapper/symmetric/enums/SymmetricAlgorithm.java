package com.wrapper.symmetric.enums;


import java.util.Arrays;


/**
 * List of Currently Supported Cryptographic Algorithms
 */
public enum SymmetricAlgorithm {

    AES_CBC_128_NoPadding("AES_CBC_128_NoPadding"),
    AES_CBC_128_PKCS7Padding("AES_CBC_128_PKCS7Padding"), //Enabled For CSHARP/DOTNET
    AES_CBC_128_PKCS5Padding("AES_CBC_128_PKCS5Padding"),
    AES_CBC_192_PKCS5Padding("AES_CBC_192_PKCS5Padding"),
    AES_CBC_256_PKCS5Padding("AES_CBC_256_PKCS5Padding"),
    AES_GCM_128_NoPadding("AES_GCM_128_NoPadding"),
    AES_GCM_192_NoPadding("AES_GCM_192_NoPadding"),
    AES_GCM_256_NoPadding("AES_GCM_256_NoPadding"),
    DEFAULT("AES_GCM_128_NoPadding"); //Default should be in the last of all the ENUM's


    public String getLabel() {
        return label;
    }

    private final String label;

    public static SymmetricAlgorithm fromLabel(String label) {

        return Arrays.stream(SymmetricAlgorithm.values()).filter(val -> val.getLabel().equals(label)).findFirst().orElseThrow(() -> new IllegalArgumentException("The Selected Algorithm is Currently Not Supported" + label));
    }

    private SymmetricAlgorithm(String label) {
        this.label = label;
    }


}

