/*
package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResultGCM;
import com.wrapper.symmetric.utils.Utility;
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
public class SymmetricWrapperCopy implements SymmetricWrap {


    private Cipher cipher;

    private Random random;

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;


    */
/**
 * Encryption with default key, iv and algorithm
 *
 * @param plaintext
 * @return
 * @throws Exception
 * <p>
 * Encryption with default iv and algorithm
 * @param secretKey
 * @param plaintext
 * @return
 * @throws Exception
 * <p>
 * Encryption with default key, iv
 * @param symmetricAlgorithm
 * @param plaintext
 * @return
 * @throws Exception
 * <p>
 * Encryption with default iv
 * @param symmetricAlgorithm
 * @param secretKey
 * @param plaintext
 * @return
 * @throws Exception
 *//*

    public SymmetricEncryptionResult encrypt(byte[] plaintext) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, plaintext);
    }

    */
/**
 * Encryption with default iv and algorithm
 *
 * @param secretKey
 * @param plaintext
 * @return
 * @throws Exception
 *//*

    public SymmetricEncryptionResult encrypt(SecretKey secretKey, byte[] plaintext) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, secretKey, plaintext);
    }

    */
/**
 * Encryption with default key, iv
 *
 * @param symmetricAlgorithm
 * @param plaintext
 * @return
 * @throws Exception
 *//*

    public SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] plaintext) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        return encrypt(symmetricAlgorithm, secretKey, plaintext);
    }

    */
/**
 * Encryption with default iv
 *
 * @param symmetricAlgorithm
 * @param secretKey
 * @param plaintext
 * @return
 * @throws Exception
 *//*

    public SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
            return encryptWithGCM(symmetricAlgorithm, secretKey, plaintext);
        }

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIvRest();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    public SymmetricDecryptionResult decrypt(final SymmetricEncryptionResult symmetricEncryptionResult) throws Exception {

        if (symmetricEncryptionResult.symmetricAlgorithm().getLabel().startsWith("AES_GCM")) {
            return decryptWithGCM(symmetricEncryptionResult);
        }

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(symmetricEncryptionResult.iv()));

        byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());

        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }

    private SymmetricEncryptionResult encryptWithGCM(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateNonceGCM();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    private SymmetricDecryptionResult decryptWithGCM(final SymmetricEncryptionResult symmetricEncryptionResult) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, symmetricEncryptionResult.iv()));

        byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());


        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }

    public SymmetricEncryptionResult encryptWithGCMAndAssociatedData(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateNonceGCM();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    public SymmetricDecryptionResult decryptWithGCMAndAssociatedData(final SymmetricEncryptionResultGCM symmetricEncryptionResultGCM) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResultGCM.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResultGCM.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResultGCM.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, symmetricEncryptionResultGCM.iv()));

        if (symmetricEncryptionResultGCM.associatedData() != null && symmetricEncryptionResultGCM.associatedData().length > 0) {
            cipher.updateAAD(symmetricEncryptionResultGCM.associatedData());
        }

        byte[] plaintext = cipher.doFinal(symmetricEncryptionResultGCM.ciphertext());

        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResultGCM.symmetricAlgorithm());
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


}
*/
