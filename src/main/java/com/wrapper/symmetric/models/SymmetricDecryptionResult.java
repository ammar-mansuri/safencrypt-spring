package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricDecryptionResult(byte[] plainText, SymmetricAlgorithm symmetricAlgorithm) {


}