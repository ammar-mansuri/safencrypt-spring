package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.builder.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static com.wrapper.symmetric.utils.Utility.getKeyAlgorithm;


@SpringBootTest(classes = {Application.class})
class SymmetricImplTest {

    @Test
    void testSymmetricEncryptionUsingAllDefaults() {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryptWithDefaultKeyGen()
                .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();


        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption()
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingDefaultAlgorithm() {


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption()
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("Hello World 121@#".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption()
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals("Hello World 121@#", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingDefaultKey() {


        SymmetricEncryptionResult symmetricEncryptionResult =
                SymmetricEncryptionBuilder.encryptWithDefaultKeyGen(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .plaintext("1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals("1232F #$$^%$^ Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingKeyLoading() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_192_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmithoutAssociateData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmWithAssociateData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext(), associatedData)
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingInsecureAlgorithm() {

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricEncryptionBuilder.encryptWithDefaultKeyGen(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                        .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt()
        );
        System.err.println(exception.getMessage());


    }


    @Test
    void testSymmetricEncryptionUsingGcmWithTagMismatch() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        AEADBadTagException exception = Assertions.assertThrows(AEADBadTagException.class, () ->
                SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                        .iv(symmetricEncryptionResult.iv())
                        .cipherText(symmetricEncryptionResult.ciphertext(), associatedDataModified)
                        .decrypt());
        System.err.println(exception.getMessage());

    }

    @Test
    void testSymmetricEncryptionUsingIncorrectKeyLength() {

        // Create a SecretKey object using the constant key material with 136 Bits
        byte[] keyMaterial = {0x021, 0xE, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x0A};
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");


        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                        .key(secretKey)
                        .plaintext("Testing Incorrect Key Length".getBytes())
                        .encrypt());
        System.err.println(exception.getMessage());

    }

}
