package com.wrapper.builder;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class SymmetricEncryptionBuilderBuilderTest {


    @Test
    public void testBuilderAES_GCM() {


        SymmetricEncryptionBuilder.createEncryptionBuilder()
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testBuilderAES_GCMWithAssociatedData() throws Exception {
        SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.DEFAULT)
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .optionalAssociatedData("ads".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testBuilderAES_CBC() throws Exception {
        SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8))
                    .optionalAssociatedData("ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SymmetricEncryptionResult symmetricEncryptionResult = new SymmetricEncryptionResult("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "ciphertext".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricEncryptionBuilder.createDecryptionBuilder()
                    .optionalAssociatedData("associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt(symmetricEncryptionResult);
        });


    }

    @Test
    public void testBuilderForDefaultAlgorithm() {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder()
                .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricEncryptionBuilder.createDecryptionBuilder().decrypt(symmetricEncryptionResult);
    }


}
