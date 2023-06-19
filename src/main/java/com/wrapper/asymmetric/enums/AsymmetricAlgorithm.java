package com.wrapper.asymmetric.enums;


import java.util.Arrays;


/**
 * List of Currently Supported Cryptographic Algorithms
 */
public enum AsymmetricAlgorithm {

    RSA_ECB_2048_PKCS1Padding("RSA_ECB_2048_PKCS1Padding"),
    //    RSA_OAEP_SHA_256("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
//    RSA_OAEP_SHA_512("RSA/ECB/OAEPWithSHA-512AndMGF1Padding"),
    DEFAULT("RSA_ECB_2048_PKCS1Padding"); //Default should be in the last of all the ENUM's


    public String getLabel() {
        return label;
    }

    private final String label;

    public static AsymmetricAlgorithm fromLabel(String label) {

        return Arrays.stream(AsymmetricAlgorithm.values()).filter(val -> val.getLabel().equals(label)).findFirst().orElseThrow(() -> new IllegalArgumentException("The Selected Algorithm is Currently Not Supported " + label));
    }

    private AsymmetricAlgorithm(String label) {
        this.label = label;
    }


}

