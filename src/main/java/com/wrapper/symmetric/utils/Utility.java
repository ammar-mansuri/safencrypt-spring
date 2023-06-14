package com.wrapper.symmetric.utils;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;

import java.util.Base64;

public class Utility {

    public static String getSimpleAlgorithm(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[0];
    }


    public static String getAlgorithmForCipher(SymmetricAlgorithm symmetricAlgorithm) {

        final String[] algo = symmetricAlgorithm.getLabel().split("_");
        return algo[0] + "/" + algo[1] + "/" + algo[3];
    }

    public static String getModeOfOperation(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[1];
    }

    public static Integer getAlgorithmBytes(SymmetricAlgorithm symmetricAlgorithm) {

        return Integer.valueOf(symmetricAlgorithm.getLabel().split("_")[2]);
    }

    public static String getPadding(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[3];
    }

    public static SymmetricEncryptionBase64 getEncodedResult(final SymmetricEncryptionResult symmetricEncryptionResult) {
        return new SymmetricEncryptionBase64(
                Base64.getEncoder().encodeToString(symmetricEncryptionResult.iv()),
                Base64.getEncoder().encodeToString(symmetricEncryptionResult.key()),
                Base64.getEncoder().encodeToString(symmetricEncryptionResult.ciphertext()),
                null,
                symmetricEncryptionResult.symmetricAlgorithm());
    }
    
}