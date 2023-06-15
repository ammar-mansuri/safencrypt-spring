package com.wrapper.builder;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricBuilder;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class SymmetricBuilderBuilderTest {


    @Test
    public void testBuilderAES_GCM() {


        SymmetricBuilder.createEncryptionBuilder()
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testBuilderAES_GCMWithAssociatedData() throws Exception {
        SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.DEFAULT)
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .optionalAssociatedData("ads".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testBuilderAES_CBC() throws Exception {
        SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8))
                    .optionalAssociatedData("ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SymmetricEncryptionResult symmetricEncryptionResult = new SymmetricEncryptionResult("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "ciphertext".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricBuilder.createDecryptionBuilder()
                    .optionalAssociatedData("associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt(symmetricEncryptionResult);
        });


    }

    @Test
    public void testBuilderForDefaultAlgorithm() {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder()
                .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricBuilder.createDecryptionBuilder().decrypt(symmetricEncryptionResult);
    }


}
