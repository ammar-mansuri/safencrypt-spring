package com.wrapper.symmetric.service;

import com.wrapper.symmetric.config.InteroperabilitySymmetricEncryptionConfig;
import com.wrapper.symmetric.config.SymmetricEncryptionConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.utils.Utility;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Random;

@Service
public class SymmetricWrapper {

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;


    private InteroperabilitySymmetricEncryptionConfig interoperabilitySymmetricEncryptionConfig;
    private SymmetricEncryptionConfig symmetricEncryptionConfig;

    @Autowired
    public SymmetricWrapper(SymmetricEncryptionConfig symmetricEncryptionConfig, InteroperabilitySymmetricEncryptionConfig interoperabilitySymmetricEncryptionConfig) {
        this.symmetricEncryptionConfig = symmetricEncryptionConfig;
        this.interoperabilitySymmetricEncryptionConfig = interoperabilitySymmetricEncryptionConfig;
    }

    @SneakyThrows
    protected SymmetricEncryptionResult encrypt(SymmetricEncryptionBuilder symmetricEncryptionBuilder) {

        if (!isAlgorithmSecure(symmetricEncryptionBuilder.getSymmetricAlgorithm())) {
            throw new Exception(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", symmetricEncryptionBuilder.getSymmetricAlgorithm().getLabel()));
        }

        SecretKey secretKey = symmetricEncryptionBuilder.getKey();

        if (!isKeyDefined(symmetricEncryptionBuilder)) {

            KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricEncryptionBuilder.getSymmetricAlgorithm()));
            kg.init(Utility.getAlgorithmBytes(symmetricEncryptionBuilder.getSymmetricAlgorithm()));
            secretKey = kg.generateKey();
        }

        if (isGCM(symmetricEncryptionBuilder.getSymmetricAlgorithm())) {
            return encryptWithGCM(symmetricEncryptionBuilder.getSymmetricAlgorithm(), secretKey, symmetricEncryptionBuilder.getPlaintext(), symmetricEncryptionBuilder.getAssociatedData());
        }

        return encrypt(symmetricEncryptionBuilder.getSymmetricAlgorithm(), secretKey, symmetricEncryptionBuilder.getPlaintext());
    }


    private SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIvRest();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    private SymmetricEncryptionResult encryptWithGCM(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) throws Exception {

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateNonceGCM();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    @SneakyThrows
    protected SymmetricDecryptionResult decrypt(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) {

        if (!isAlgorithmSecure(symmetricEncryptionResult.symmetricAlgorithm())) {
            throw new Exception(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", symmetricEncryptionResult.symmetricAlgorithm().getLabel()));
        }

        return isGCM(symmetricEncryptionResult.symmetricAlgorithm()) ? decryptWithGCM(symmetricEncryptionResult, associatedData) : decryptRest(symmetricEncryptionResult);
    }

    private SymmetricDecryptionResult decryptRest(final SymmetricEncryptionResult symmetricEncryptionResult) throws Exception {

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        final SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(symmetricEncryptionResult.iv()));

        final byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());

        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }

    private SymmetricDecryptionResult decryptWithGCM(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) throws Exception {

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        final SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, symmetricEncryptionResult.iv()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());


        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }


    private boolean isGCM(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().startsWith("AES_GCM");
    }

    private boolean isKeyDefined(SymmetricEncryptionBuilder symmetricEncryptionBuilder) {
        return symmetricEncryptionBuilder.getKey() != null && symmetricEncryptionBuilder.getKey().getEncoded().length > 0;
    }

    private IvParameterSpec generateIvRest() {

        final byte[] iv = new byte[REST_IV_SIZE];
        final Random random = new SecureRandom();
        random.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        return ivSpec;
    }

    private IvParameterSpec generateNonceGCM() {

        final byte[] nonce = new byte[GCM_IV_SIZE];
        final Random random = new SecureRandom();
        random.nextBytes(nonce);
        final IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        return ivSpec;
    }

    public boolean isAlgorithmSecure(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricEncryptionConfig.algorithms().contains(symmetricAlgorithm.getLabel());

    }


}
