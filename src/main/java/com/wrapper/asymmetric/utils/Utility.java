package com.wrapper.asymmetric.utils;

import com.wrapper.asymmetric.enums.AsymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;

import java.util.Base64;

public class Utility {

    public static String getSimpleAlgorithm(AsymmetricAlgorithm asymmetricAlgorithm) {

        return asymmetricAlgorithm.getLabel().split("_")[0];
    }


    public static String getAlgorithmForCipher(AsymmetricAlgorithm asymmetricAlgorithm) {

        final String[] algo = asymmetricAlgorithm.getLabel().split("_");
        return algo[0] + "/" + algo[1] + "/" + algo[3];
    }

    public static String getModeOfOperation(AsymmetricAlgorithm asymmetricAlgorithm) {

        return asymmetricAlgorithm.getLabel().split("_")[1];
    }

    public static Integer getAlgorithmBytes(AsymmetricAlgorithm asymmetricAlgorithm) {

        return Integer.valueOf(asymmetricAlgorithm.getLabel().split("_")[2]);
    }

    public static String getPadding(AsymmetricAlgorithm asymmetricAlgorithm) {

        return asymmetricAlgorithm.getLabel().split("_")[3];
    }

    public static SymmetricEncryptionBase64 getSymmetricEncodedResult(final SymmetricEncryptionResult symmetricEncryptionResult, String keyAlias) {
        return new SymmetricEncryptionBase64(
                Base64.getEncoder().encodeToString(symmetricEncryptionResult.iv()),
                keyAlias,
                Base64.getEncoder().encodeToString(symmetricEncryptionResult.ciphertext()),
                symmetricEncryptionResult.symmetricAlgorithm());
    }

}
