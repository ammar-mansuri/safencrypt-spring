package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;

import javax.crypto.SecretKey;

public interface SymmetricWrap {

    public SymmetricEncryptionResult encrypt(byte[] plaintext) throws Exception;

    public SymmetricEncryptionResult encrypt(SecretKey secretKey, byte[] plaintext) throws Exception;

    public SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] plaintext) throws Exception;

    public SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception;

    public SymmetricDecryptionResult decrypt(final SymmetricEncryptionResult symmetricEncryptionResult) throws Exception;

}
