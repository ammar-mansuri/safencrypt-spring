package com.wrapper.asymmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record ASymmetricEncryptionResult(byte[] iv, byte[] key, byte[] ciphertext,
                                         SymmetricAlgorithm symmetricAlgorithm) {


}