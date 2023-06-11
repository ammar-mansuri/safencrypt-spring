package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricEncryptionGCM(byte[] iv, byte[] key, byte[] ciphertext, byte[] associatedData,
                                     SymmetricAlgorithm symmetricAlgorithm) {


}