package com.wrapper.asymmetric.models;

import com.wrapper.asymmetric.enums.AsymmetricAlgorithm;

import java.security.KeyPair;

public record AsymmetricEncryptionResult(KeyPair keyPair, byte[] ciphertext,
                                         AsymmetricAlgorithm asymmetricAlgorithm) {


}