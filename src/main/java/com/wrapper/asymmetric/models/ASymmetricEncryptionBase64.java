package com.wrapper.asymmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record ASymmetricEncryptionBase64(String iv, String key, String ciphertext, String plainText,
                                         SymmetricAlgorithm symmetricAlgorithm) {
}