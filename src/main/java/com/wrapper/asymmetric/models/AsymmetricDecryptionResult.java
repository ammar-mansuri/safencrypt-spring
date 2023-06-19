package com.wrapper.asymmetric.models;

import com.wrapper.asymmetric.enums.AsymmetricAlgorithm;

public record AsymmetricDecryptionResult(byte[] plainText, AsymmetricAlgorithm symmetricAlgorithm) {


}