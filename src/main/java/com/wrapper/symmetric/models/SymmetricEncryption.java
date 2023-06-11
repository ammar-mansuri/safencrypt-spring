package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricEncryption(byte[] iv, byte[] key, byte[] ciphertext, SymmetricAlgorithm symmetricAlgorithm) {


}