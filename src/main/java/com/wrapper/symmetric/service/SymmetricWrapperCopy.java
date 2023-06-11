/*
package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.CipherAlgorithm;
import com.wrapper.symmetric.utils.Utility;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

//@Service
public class SymmetricWrapperCopy {


    private static Cipher cipher;



    */
/*private SymmetricWrapper(CipherAlgorithm cipherAlgorithm, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {


 *//*
 */
/*KeyGenerator kg = KeyGenerator.getInstance(Utility.getAlgorithm(cipherAlgorithm));
        kg.init(Utility.getAlgorithmBytes(cipherAlgorithm));
        SecretKey secretKey = kg.generateKey();

        SecretKey secretKey = new SecretKeySpec(key, Utility.getAlgorithm(cipherAlgorithm));

        // Initialize the cipher using the specified parameters
        cipher = Cipher.getInstance(Utility.getAlgorithm(cipherAlgorithm));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);*//*
 */
/*
    }*//*


    public byte[] encrypt(byte[] plaintext) throws Exception {

        return encrypt(CipherAlgorithm.DEFAULT, plaintext);
    }

    public byte[] encrypt(SecretKey secretKey, byte[] plaintext) throws Exception {

        return encrypt(CipherAlgorithm.DEFAULT, secretKey, plaintext);
    }

    public byte[] encrypt(CipherAlgorithm cipherAlgorithm, byte[] plaintext) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(cipherAlgorithm));
        kg.init(Utility.getAlgorithmBytes(cipherAlgorithm));
        SecretKey secretKey = kg.generateKey();

        return encrypt(cipherAlgorithm, secretKey, plaintext);
    }

    public byte[] encrypt(CipherAlgorithm cipherAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {


        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(cipherAlgorithm));

        // Generate a random IV
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);


        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return result;
    }

    public byte[] decrypt(CipherAlgorithm cipherAlgorithm, SecretKey secretKey, byte[] ciphertext) throws Exception {

        cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(cipherAlgorithm));

        // Extract the IV from the ciphertext
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(ciphertext, 0, iv, 0, iv.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Decrypt the ciphertext
        byte[] encrypted = new byte[ciphertext.length - iv.length];
        System.arraycopy(ciphertext, iv.length, encrypted, 0, encrypted.length);

        return cipher.doFinal(encrypted);
    }

 */
/*   public static CipherResult encryptWithIv(CipherAlgorithm cipherAlgorithm, byte[] key, byte[] plaintext) throws Exception {
        byte[] ciphertext = encrypt(cipherAlgorithm, key, plaintext);
        byte[] iv = new byte[cipherAlgorithm.name().equals("AES_CBC") ? 16 : 12];
        System.arraycopy(ciphertext, 0, iv, 0, iv.length);
        byte[] encrypted = new byte[ciphertext.length - iv.length];
        System.arraycopy(ciphertext, iv.length, encrypted, 0, encrypted.length);
        return new CipherResult(iv, ciphertext);
    }


    public static class CipherResult {
        private final byte[] iv;
        private final byte[] ciphertext;

        public CipherResult(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }
    }*//*

}
*/
