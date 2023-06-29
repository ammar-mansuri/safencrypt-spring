package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.models.SymmetricPlain;
import com.wrapper.symmetric.service.KeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.wrapper.symmetric.utils.Utility.getKeyAlgorithm;


@SpringBootTest(classes = {Application.class})
class SymmetricImplTest {

    @Test
    void testSymmetricEncryptionUsingAllDefaults1() {

        byte[] plainText = "Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption()
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingDefaultAlgorithm2() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption()
                        .key(KeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_GCM_128_NoPadding))
                        .plaintext(plainText)
                        .encrypt();


        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption()
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingDefaultKey3() {

        byte[] plainText = "1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingAlgoKeyLoading4() {

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_192_NoPadding;
        SecretKey secretKey = KeyGenerator.generateSymmetricKey(symmetricAlgorithm);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(symmetricAlgorithm)
                        .key(secretKey)
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmithoutAssociateData() {

        byte[] plainText = "Hello World JCA WRAPPER Using GCM Without AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmWithAssociateData5() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "I am associated data".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                        .key(KeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                        .plaintext(plainText, associatedData)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedData)
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingCBC6() {

        byte[] plainText = "TESTING CBC 128 With PKCS5 PADDING".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingInsecureAlgorithm() {

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                        .generateKey()
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


        SymmetricCipher symmetricCipher = SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(KeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricCipher.key(), getKeyAlgorithm(symmetricCipher.symmetricAlgorithm())))
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedDataModified)
                        .decrypt());
        System.err.println(exception.getMessage());

    }

    @Test
    void testSymmetricEncryptionUsingIncorrectKeyLength() {

        // Create a SecretKey object using the constant key material with 136 Bits
        byte[] keyMaterial = {0x021, 0xE, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x0A};
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");


        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                        .key(secretKey)
                        .plaintext("Testing Incorrect Key Length".getBytes())
                        .encrypt());

        System.err.println(exception.getMessage());

    }


    @Test
    void testSymmetricDecryptionUsingIncorrectKey() {

        // Create a SecretKey object using the constant key material with 136 Bits
        byte[] keyMaterial = {99, 22, 98, -63, 12, 117, -55, 24, 0, -121, -116, 105, 91, 83, 113, -71};
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");

        byte[] keyMaterial2 = {0x2c, 0x25, 0x7a, 0x2E, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x0A};
        SecretKey secretKey1 = new SecretKeySpec(keyMaterial2, "AES");

//        SymmetricEncryptionBase64[iv=w0dxo8QyaB1JGDbtnbHh8A==, keyAlias=ZFZA/7honlNzhWyJYRDSuw==, ciphertext=Sj1D4fTUrXVUOH51HaCH/YmTqiuun2R+B9BUXLdxRXd/+OWb8e6LriH3aIYhmVLf, symmetricAlgorithm=AES_CBC_128_PKCS5Padding]
//        SymmetricEncryptionBase64[iv=lG2LvqxxUKng/U2BCfg4vQ==, keyAlias=R70aIVGl1ot6kHGyvpiEQw==, ciphertext=jtDNcVdQWM85VIc0z7l6J1lIGvx72kWeduRAiEoighlRb2W1rbD8s/u3N5weLEnH, symmetricAlgorithm=AES_CBC_128_PKCS5Padding]

        SafencryptException exception = Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(new SecretKeySpec(Base64.getDecoder().decode("R70aIVGl1ot6kHGyvpiEQw=="), "AES"))
                        .iv(Base64.getDecoder().decode("w0dxo8QyaB1JGDbtnbHh8A=="))
                        .cipherText(Base64.getDecoder().decode("Sj1D4fTUrXVUOH51HaCH/YmTqiuun2R+B9BUXLdxRXd/+OWb8e6LriH3aIYhmVLf"))
                        .decrypt());

        System.err.println(exception.getMessage());
    }

}
