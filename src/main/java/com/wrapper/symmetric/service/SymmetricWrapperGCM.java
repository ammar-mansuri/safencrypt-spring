package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryption;
import com.wrapper.symmetric.models.SymmetricEncryptionGCM;
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
public class SymmetricWrapperGCM {


    private Cipher cipher;

    private Random random;

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;


    /**
     * Encryption with default key, iv and algorithm
     *
     * @param plaintext
     * @return
     * @throws Exception
     */
    public SymmetricEncryptionGCM encrypt(byte[] plaintext) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, plaintext, null);
    }

    public SymmetricEncryptionGCM encrypt(byte[] plaintext, byte[] associatedData) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, plaintext, associatedData);
    }

    /**
     * Encryption with default iv and algorithm
     *
     * @param secretKey
     * @param plaintext
     * @return
     * @throws Exception
     */
    public SymmetricEncryptionGCM encrypt(SecretKey secretKey, byte[] plaintext, byte[] associatedData) throws Exception {

        return encrypt(SymmetricAlgorithm.DEFAULT, secretKey, plaintext, associatedData);
    }

    /**
     * Encryption with default key, iv
     *
     * @param symmetricAlgorithm
     * @param plaintext
     * @return
     * @throws Exception
     */
    public SymmetricEncryptionGCM encrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] plaintext, byte[] associatedData) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        return encrypt(symmetricAlgorithm, secretKey, plaintext, associatedData);
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
    public SymmetricEncryptionGCM encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateNonceGCM();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }


        byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionGCM(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, associatedData, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    public SymmetricDecryption decrypt(final SymmetricEncryptionGCM symmetricEncryptionGCM) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionGCM.symmetricAlgorithm()));

        SecretKey secretKey = new SecretKeySpec(symmetricEncryptionGCM.key(), Utility.getSimpleAlgorithm(symmetricEncryptionGCM.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, symmetricEncryptionGCM.iv()));

        if (symmetricEncryptionGCM.associatedData() != null && symmetricEncryptionGCM.associatedData().length > 0) {
            cipher.updateAAD(symmetricEncryptionGCM.associatedData());
        }

        byte[] plaintext = cipher.doFinal(symmetricEncryptionGCM.ciphertext());


        return new SymmetricDecryption(plaintext, symmetricEncryptionGCM.symmetricAlgorithm());
    }


    private IvParameterSpec generateNonceGCM() {

        byte[] nonce = new byte[GCM_IV_SIZE];
        random = new SecureRandom();
        random.nextBytes(nonce);
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        return ivSpec;
    }


}
