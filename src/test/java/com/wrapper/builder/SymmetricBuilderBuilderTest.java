package com.wrapper.builder;

import com.wrapper.Application;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import com.wrapper.symmetric.utils.Utility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static com.wrapper.symmetric.utils.Utility.getSimpleAlgorithm;

@SpringBootTest(classes = {Application.class})
public class SymmetricBuilderBuilderTest {


    @Test
    public void testBuilderAES_GCM() {
        SymmetricEncryptionBuilder.encryption()
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testBuilderAES_GCMWithAssociatedData() {
        SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.DEFAULT)
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("ds".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testBuilderAES_CBC() {
        SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    public void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .key(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SymmetricEncryptionResult symmetricEncryptionResult = new SymmetricEncryptionResult("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "ciphertext".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricEncryptionBuilder.decryption()
                    .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                    .iv(symmetricEncryptionResult.iv())
                    .cipherText(symmetricEncryptionResult.ciphertext(), "associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt();
        });


    }

    @Test
    public void testBuilderForDefaultAlgorithm() {

        SymmetricEncryptionResult symmetricEncryptionResult =
                SymmetricEncryptionBuilder.encryptWithDefaultKeyGen()
                        .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SymmetricEncryptionBuilder
                .decryption()
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();
    }


}
