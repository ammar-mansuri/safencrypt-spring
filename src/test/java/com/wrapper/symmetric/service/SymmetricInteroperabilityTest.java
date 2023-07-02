package com.wrapper.symmetric.service;

import com.wrapper.Application;
import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.builder.SymmetricInteroperableBuilder;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.enums.SymmetricInteroperabilityLanguages;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.models.SymmetricCipherBase64;
import com.wrapper.symmetric.models.SymmetricPlain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@SpringBootTest(classes = {Application.class})
class SymmetricInteroperabilityTest {

    @Test
    void testSymmetricInteroperabilityWithCSharp() {

        byte[] plainText = "Test for C# Which Uses Algorithm that Doesnt Ensure Integrity".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.CSharp)
                .plaintext(plainText)
                .encrypt();

        SymmetricPlain symmetricPlain = SymmetricInteroperableBuilder
                .createDecryptionBuilder(SymmetricInteroperabilityLanguages.CSharp)
                .keyAlias(symmetricEncryptionResult.keyAlias())
                .ivBase64(symmetricEncryptionResult.iv())
                .cipherTextBase64(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));
        System.out.println(symmetricEncryptionResult);
    }


    @Test
    void testSymmetricEncryptionInteroperabilityWithPythonWithGcmAndAssociateData() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }


    @Test
    void testSymmetricDecryptionInteroperabilityWithPythonWithGcmAndAssociateData() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }


    @Test
    void testSymmetricEncryptionInteroperabilityWithPython() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }

    @Test
    void generalEncryptForPython() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER Encrypt For Python".getBytes(StandardCharsets.UTF_8);


        SymmetricCipher symmetricCipher = SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        System.out.println(symmetricCipher);

    }


    @Test
    void generalDecryptFromPython() {

        byte[] ciphertextBytes = Base64.getDecoder().decode("lJipwcZuQ+0no1s=".getBytes());
        byte[] tagBytes = Base64.getDecoder().decode("ypgsDoaFKGj06ljQ".getBytes());
        byte[] ciphertextTagBytes = new byte[ciphertextBytes.length + tagBytes.length];
        System.arraycopy(ciphertextBytes, 0, ciphertextTagBytes, 0, ciphertextBytes.length);
        System.arraycopy(tagBytes, 0, ciphertextTagBytes, ciphertextBytes.length, tagBytes.length);

        SymmetricPlain symmetricPlain = SymmetricBuilder.decryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(Base64.getDecoder().decode("2Gn4xCkAioEBk21QY9BWCw==".getBytes()))
                .iv(Base64.getDecoder().decode("MXA8iL1gvl6i7Qx6".getBytes()))
                .cipherText(ciphertextTagBytes)
                .decrypt();

        Assertions.assertEquals("Hello World", new String(symmetricPlain.plainText(), StandardCharsets.UTF_8));

    }

}
