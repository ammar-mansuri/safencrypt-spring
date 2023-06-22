package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static com.wrapper.symmetric.utils.Utility.getSimpleAlgorithm;


@SpringBootTest(classes = {Application.class})
public class SymmetricImplTest {
    
    @Test
    public void testSymmetricEncryptionUsingAllDefaults() {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryptWithDefaultKeyGen()
                .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();


        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption()
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testSymmetricEncryptionUsingDefaultAlgorithm() {


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption()
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("Hello World 121@#".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption()
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals("Hello World 121@#", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingDefaultKey() {


        SymmetricEncryptionResult symmetricEncryptionResult =
                SymmetricEncryptionBuilder.encryptWithDefaultKeyGen(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .plaintext("1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals("1232F #$$^%$^ Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingKeyLoading() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_192_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGcmithoutAssociateData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext())
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGcmWithAssociateData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                .iv(symmetricEncryptionResult.iv())
                .cipherText(symmetricEncryptionResult.ciphertext(), associatedData)
                .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingInsecureAlgorithm() {

        Assertions.assertThrows(SafencryptException.class, () ->
                SymmetricEncryptionBuilder.encryptWithDefaultKeyGen(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                        .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                        .encrypt()
        );

    }


    @Test
    public void testSymmetricEncryptionUsingGcmWithTagMismatch() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText, associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        Assertions.assertThrows(AEADBadTagException.class, () ->
                SymmetricEncryptionBuilder.decryption(symmetricEncryptionResult.symmetricAlgorithm())
                        .key(new SecretKeySpec(symmetricEncryptionResult.key(), getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm())))
                        .iv(symmetricEncryptionResult.iv())
                        .cipherText(symmetricEncryptionResult.ciphertext(), associatedDataModified)
                        .decrypt());
    }
}
