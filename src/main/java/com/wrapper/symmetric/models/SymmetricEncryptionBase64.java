package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricEncryptionBase64(String iv, String keyAlias, String ciphertext,
                                        SymmetricAlgorithm symmetricAlgorithm) {
}