package com.wrapper.symmetric.service;

import com.wrapper.Application;
import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.models.SymmetricPlain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;


@SpringBootTest(classes = {Application.class})
class SymmetricImplFunctionalTest {

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
                        .key(symmetricCipher.key())
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
                        .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_GCM_128_NoPadding))
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption()
                        .key(symmetricCipher.key())
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
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingAlgoKeyLoading4() {

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_192_NoPadding;
        byte[] secretKey = SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(symmetricAlgorithm)
                        .key(secretKey)
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
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
                        .key(symmetricCipher.key())
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
                        .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                        .plaintext(plainText, associatedData)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
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
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }


}
