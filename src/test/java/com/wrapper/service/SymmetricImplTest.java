package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricBuilder;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;


@SpringBootTest(classes = {Application.class})
public class SymmetricImplTest {


    @Test
    public void testSymmetricEncryptionUsingAllDefaults() {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder()
                .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();


        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testSymmetricEncryptionUsingDefaultAlgorithm() {


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder()
                .key(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("Hello World 121@#".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals("Hello World 121@#", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingDefaultKey() {


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .plaintext("1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals("1232F #$$^%$^ Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingKeyLoading() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_192_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(symmetricAlgorithm)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGcmWithoutAssociatedData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_256_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(symmetricAlgorithm)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGCMWithAssociatedData() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(symmetricAlgorithm)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .optionalAssociatedData(associatedData)
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingInsecureAlgorithm() {

        Assertions.assertThrows(SafencryptException.class, () -> {
            SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                    .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });
    }


    @Test
    public void testSymmetricEncryptionUsingGCMWithTagMismatch() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(symmetricAlgorithm)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        Assertions.assertThrows(AEADBadTagException.class, () ->
                SymmetricBuilder.createDecryptionBuilder()
                        .optionalAssociatedData(associatedDataModified)
                        .decrypt(symmetricEncryptionResult));
    }


}
