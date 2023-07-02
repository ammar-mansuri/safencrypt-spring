package com.wrapper.symmetric.service;

import com.wrapper.Application;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricCipher;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@SpringBootTest(classes = {Application.class})
public class SymmetricImplAlternativeTest {

    @Test
    void testSymmetricEncryptionUsingInsecureAlgorithm() {

        SafencryptException enCryptException = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                        .generateKey()
                        .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt()
        );
        System.err.println("During encryption: " + enCryptException.getMessage());

        SafencryptException deCryptException = Assertions.assertThrows(SafencryptException.class, () -> {
                    SymmetricCipher symmetricCipher =
                            SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                                    .generateKey()
                                    .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                                    .encrypt();
                    SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                            .key(symmetricCipher.key())
                            .iv(symmetricCipher.iv())
                            .cipherText(Base64.getDecoder().decode("Sj1D4fTU"))
                            .decrypt();
                }
        );
        System.err.println("During decryption: " + deCryptException.getMessage());
    }

    @Test
    void testSymmetricEncryptionUsingIncorrectAlgorithm() {


        SafencryptException enCryptException = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AESS_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt()
        );
        System.err.println("During encryption: " + enCryptException.getMessage());


        SafencryptException deCryptException = Assertions.assertThrows(SafencryptException.class, () -> {
                    SymmetricCipher symmetricCipher =
                            SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                                    .generateKey()
                                    .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                                    .encrypt();
                    SymmetricBuilder.decryption(SymmetricAlgorithm.AESS_CBC_128_PKCS5Padding)
                            .key(symmetricCipher.key())
                            .iv(symmetricCipher.iv())
                            .cipherText(Base64.getDecoder().decode("Sj1D4fTU"))
                            .decrypt();
                }
        );
        System.err.println("During decryption: " + deCryptException.getMessage());
    }

    @Test
    void testSymmetricEncryptionUsingIncorrectLengthIV() {

        byte[] randomIv = new byte[23];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomIv);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(symmetricCipher.key())
                        .iv(randomIv)
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt()
        );
        System.err.println(exception.getMessage());
    }

    @Test
    void testSymmetricEncryptionUsingIncorrectPadding() {


        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_NopPadding)
                        .generateKey()
                        .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt()
        );
        System.err.println(exception.getMessage());
    }


    @Test
    void testSymmetricEncryptionUsingIncorrectKeyLength() {

        byte[] randomKey = new byte[33];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomKey);


        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                        .key(randomKey)
                        .plaintext("Testing Incorrect Key Length".getBytes())
                        .encrypt());

        System.err.println(exception.getMessage());

    }


    @Test
    @SneakyThrows
    void testSymmetricDecryptionUsingIncorrectIV_Key_Padding() {

        SymmetricCipher symmetricCipher = SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .generateKey()
                .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        byte[] randomIv_Key = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomIv_Key);
        //Incorrect IV
        SafencryptException deCryptException = Assertions.assertThrows(SafencryptException.class, () -> {

                    SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                            .key(symmetricCipher.key())
                            .iv(randomIv_Key)
                            .cipherText(symmetricCipher.ciphertext())
                            .decrypt();
                }
        );
        System.err.println(deCryptException.getMessage());
        //Incorrect Key
        SafencryptException deCryptException2 = Assertions.assertThrows(SafencryptException.class, () -> {

                    SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                            .key(randomIv_Key)
                            .iv(symmetricCipher.iv())
                            .cipherText(symmetricCipher.ciphertext())
                            .decrypt();
                }
        );
        System.err.println(deCryptException2.getMessage());
        //Incorrect Mode
        /*Exception deCryptException3 = Assertions.assertThrows(Exception.class, () -> {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmetricCipher.key(), "AES"));
            cipher.doFinal(symmetricCipher.ciphertext());
        });
        System.err.println(deCryptException3.getMessage());*/

    }

    @Test
    void testSymmetricEncryptionUsingGcmWithTagMismatch() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricCipher symmetricCipher = SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedDataModified)
                        .decrypt());
        System.err.println(exception.getMessage());

    }


    @Test
    void testSymmetricEncryptionUsingGcmWithTagMismatch_Key_IV() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        SymmetricCipher symmetricCipher = SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        //Incorrect IV
        byte[] randomIv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomIv);
        SafencryptException exception1 = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(randomIv)
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt());
        System.err.println(exception1.getMessage());


        //Incorrect Key
        byte[] randomKey = new byte[16];
        secureRandom.nextBytes(randomKey);
        SafencryptException exception2 = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(randomKey)
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt());
        System.err.println(exception2.getMessage());
    }

    @Test
    void testSymmetricEncryptionUsingGcmWithTagMismatch_AssociatedData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);
        byte[] associatedDataModified = "First test using AEADDD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher = SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedDataModified)
                        .decrypt());
        System.err.println(exception.getMessage());
    }

    @Test
    void testGcmWithIncorrectPadding() {
        //GCM with Incorrect Padding
        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_PKCS5Padding)
                        .key(SymmetricKeyGenerator.generateSymmetricKey())
                        .plaintext("Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8))
                        .encrypt());
        System.err.println(exception.getMessage());
    }
}
