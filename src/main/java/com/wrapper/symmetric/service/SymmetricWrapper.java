package com.wrapper.symmetric.service;

import com.wrapper.symmetric.config.SymmetricEncryptionConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.utils.Utility;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Random;

@Service
@NoArgsConstructor
public class SymmetricWrapper {

    private SymmetricEncryptionConfig symmetricEncryptionConfig;

    private Cipher cipher;

    private Random random;

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;


    protected SymmetricEncryptionResult encrypt(SymmetricEncryption symmetricEncryption) throws Exception {

        isAlgorithmSecure(symmetricEncryption.getSymmetricAlgorithm());

        SecretKey secretKey = symmetricEncryption.getKey();

        if (!isKeyDefined(symmetricEncryption)) {

            KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricEncryption.getSymmetricAlgorithm()));
            kg.init(Utility.getAlgorithmBytes(symmetricEncryption.getSymmetricAlgorithm()));
            secretKey = kg.generateKey();
        }

        if (isGCM(symmetricEncryption.getSymmetricAlgorithm())) {
            return encryptWithGCM(symmetricEncryption.getSymmetricAlgorithm(), secretKey, symmetricEncryption.getPlaintext(), symmetricEncryption.getAssociatedData());
        }

        return encrypt(symmetricEncryption.getSymmetricAlgorithm(), secretKey, symmetricEncryption.getPlaintext());
    }


    /**
     * Encryption with default iv
     *
     * @param symmetricAlgorithm
     * @param secretKey
     * @param plaintext
     * @return
     * @throws Exception
     */
    private SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIvRest();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    protected SymmetricDecryptionResult decrypt(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) throws Exception {

        if (isGCM(symmetricEncryptionResult.symmetricAlgorithm())) {
            return decryptWithGCM(symmetricEncryptionResult, associatedData);
        }

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(symmetricEncryptionResult.iv()));

        byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());

        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }


    private SymmetricEncryptionResult encryptWithGCM(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateNonceGCM();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    private SymmetricDecryptionResult decryptWithGCM(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, symmetricEncryptionResult.iv()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());


        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }


    private boolean isGCM(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().startsWith("AES_GCM");
    }

    private boolean isKeyDefined(SymmetricEncryption symmetricEncryption) {
        return symmetricEncryption.getKey() != null && symmetricEncryption.getKey().getEncoded().length > 0;
    }

    private IvParameterSpec generateIvRest() {

        byte[] iv = new byte[REST_IV_SIZE];
        random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        return ivSpec;
    }

    private IvParameterSpec generateNonceGCM() {

        byte[] nonce = new byte[GCM_IV_SIZE];
        random = new SecureRandom();
        random.nextBytes(nonce);
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        return ivSpec;
    }

    public boolean isAlgorithmSecure(SymmetricAlgorithm symmetricAlgorithm) {
        return true;
    }


}
