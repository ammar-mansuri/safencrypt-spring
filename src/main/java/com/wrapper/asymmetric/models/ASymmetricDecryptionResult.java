package com.wrapper.asymmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record ASymmetricDecryptionResult(byte[] plainText, SymmetricAlgorithm symmetricAlgorithm) {


}