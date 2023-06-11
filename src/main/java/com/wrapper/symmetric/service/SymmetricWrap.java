package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryption;
import com.wrapper.symmetric.models.SymmetricEncryption;

import javax.crypto.SecretKey;

public interface SymmetricWrap {

    public SymmetricEncryption encrypt(byte[] plaintext) throws Exception;

    public SymmetricEncryption encrypt(SecretKey secretKey, byte[] plaintext) throws Exception;

    public SymmetricEncryption encrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] plaintext) throws Exception;

    public SymmetricEncryption encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception;

    public SymmetricDecryption decrypt(final SymmetricEncryption symmetricEncryption) throws Exception;


}
