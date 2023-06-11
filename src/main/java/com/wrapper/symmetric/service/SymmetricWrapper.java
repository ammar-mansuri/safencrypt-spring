package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryption;
import com.wrapper.symmetric.models.SymmetricEncryption;
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
public class SymmetricWrapper implements SymmetricWrap {


    private Cipher cipher;

    private Random random;

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;


    /**
     * Encryption with default key, iv and algorithm
     *
     * @param plaintext
     * @return
     * @throws Exception
     */
    public SymmetricEncryption encrypt(byte[] plaintext) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, plaintext);
    }

    /**
     * Encryption with default iv and algorithm
     *
     * @param secretKey
     * @param plaintext
     * @return
     * @throws Exception
     */
    public SymmetricEncryption encrypt(SecretKey secretKey, byte[] plaintext) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, secretKey, plaintext);
    }

    /**
     * Encryption with default key, iv
     *
     * @param symmetricAlgorithm
     * @param plaintext
     * @return
     * @throws Exception
     */
    public SymmetricEncryption encrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] plaintext) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        return encrypt(symmetricAlgorithm, secretKey, plaintext);
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
    public SymmetricEncryption encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
            return encryptGCM(symmetricAlgorithm, secretKey, plaintext);
        }

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIvRest();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryption(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    public SymmetricDecryption decrypt(final SymmetricEncryption symmetricEncryption) throws Exception {

        if (symmetricEncryption.symmetricAlgorithm().getLabel().startsWith("AES_GCM")) {
            return decryptGCM(symmetricEncryption);
        }

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryption.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryption.key(), Utility.getSimpleAlgorithm(symmetricEncryption.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(symmetricEncryption.iv()));

        byte[] plaintext = cipher.doFinal(symmetricEncryption.ciphertext());

        return new SymmetricDecryption(plaintext, symmetricEncryption.symmetricAlgorithm());
    }

    private SymmetricEncryption encryptGCM(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateNonceGCM();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryption(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    private SymmetricDecryption decryptGCM(final SymmetricEncryption symmetricEncryption) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryption.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryption.key(), Utility.getSimpleAlgorithm(symmetricEncryption.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, symmetricEncryption.iv()));

        byte[] plaintext = cipher.doFinal(symmetricEncryption.ciphertext());


        return new SymmetricDecryption(plaintext, symmetricEncryption.symmetricAlgorithm());
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
