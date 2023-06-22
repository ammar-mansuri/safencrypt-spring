package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.enums.SymmetricInteroperabilityLanguages;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.service.SymmetricInteroperableBuilder;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.wrapper.symmetric.utils.Utility.getSimpleAlgorithm;

@SpringBootTest(classes = {Application.class})
public class SymmetricInteroperabilityTest {

    @Test
    public void testSymmetricInteroperabilityWithCSharp() {

        byte[] plainText = "Test for C# Which Uses Algorithm that Doesnt Ensure Integrity".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.CSharp)
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricInteroperableBuilder
                .createDecryptionBuilder(SymmetricInteroperabilityLanguages.CSharp)
                .keyAlias(symmetricEncryptionResult.keyAlias())
                .ivBase64(symmetricEncryptionResult.iv())
                .cipherTextBase64(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));
        System.out.println(symmetricEncryptionResult);
    }


    @Test
    public void testSymmetricEncryptionInteroperabilityWithPythonWithGcmAndAssociateData() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }


    @Test
    public void testSymmetricDecryptionInteroperabilityWithPythonWithGcmAndAssociateData() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }


    @Test
    public void testSymmetricEncryptionInteroperabilityWithPython() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricInteroperableBuilder
                .createEncryptionBuilder(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }

    @Test
    public void generalEncryptForPython() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER Encrypt For Python".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        System.out.println(symmetricEncryptionResult);

    }


    @Test
    public void generalDecryptFromPython() {

        byte[] ciphertextBytes = Base64.getDecoder().decode("lJipwcZuQ+0no1s=".getBytes());
        byte[] tagBytes = Base64.getDecoder().decode("ypgsDoaFKGj06ljQ".getBytes());
        byte[] ciphertextTagBytes = new byte[ciphertextBytes.length + tagBytes.length];
        System.arraycopy(ciphertextBytes, 0, ciphertextTagBytes, 0, ciphertextBytes.length);
        System.arraycopy(tagBytes, 0, ciphertextTagBytes, ciphertextBytes.length, tagBytes.length);

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(new SecretKeySpec(Base64.getDecoder().decode("2Gn4xCkAioEBk21QY9BWCw==".getBytes()), getSimpleAlgorithm(SymmetricAlgorithm.AES_GCM_128_NoPadding)))
                .iv(Base64.getDecoder().decode("MXA8iL1gvl6i7Qx6".getBytes()))
                .cipherText(ciphertextTagBytes)
                .decrypt();

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

}
