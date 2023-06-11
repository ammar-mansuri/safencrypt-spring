package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricDecryption(byte[] plainText, SymmetricAlgorithm symmetricAlgorithm) {


}