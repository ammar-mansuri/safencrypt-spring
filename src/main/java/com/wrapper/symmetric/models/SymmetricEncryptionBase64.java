package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricEncryptionBase64(String iv, String key, String ciphertext, String plainText,
                                        SymmetricAlgorithm symmetricAlgorithm) {


}