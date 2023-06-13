package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.symmetric.config.SymmetricEncryptionConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricEncryption;
import com.wrapper.symmetric.utils.Utility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;


@SpringBootTest(classes = {Application.class})
public class SymmetricWrapperTest {


    @Autowired
    private SymmetricEncryptionConfig symmetricEncryptionConfig;


    @Test
    public void testSymmetricEncryptionUsingAllDefaults() throws Exception {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder()
                .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryption.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testSymmetricEncryptionUsingDefaultAlgorithm() throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(SymmetricAlgorithm.DEFAULT));
        kg.init(Utility.getAlgorithmBytes(SymmetricAlgorithm.DEFAULT));
        SecretKey secretKey = kg.generateKey();


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder()
                .key(secretKey)
                .plaintext("Hello World 121@#".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryption.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals("Hello World 121@#", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingDefaultKey() throws Exception {


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .plaintext("1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryption.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals("1232F #$$^%$^ Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingKeyLoading() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_192_PKCS5Padding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                .key(secretKey)
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryption.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGCMWithOutAuthenticationTag() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryption.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGCMWithAuthenticationTag() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryption.createDecryptionBuilder()
                .optionalAssociatedData(associatedData)
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGCMWithTagMismatch() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryption.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        Assertions.assertThrows(AEADBadTagException.class, () -> {
            SymmetricEncryption.createDecryptionBuilder()
                    .optionalAssociatedData(associatedDataModified)
                    .decrypt(symmetricEncryptionResult);
        });

    }







   /* @Test
    public void encryptForPython() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResultGCM symmetricEncryptionResult = symmetricWrapperGCM.encrypt(SymmetricAlgorithm.AES_GCM_256_NoPadding, secretKey, plainText, null);


//        byte[] ciphertextBytes;
//        byte[] tagBytes;
//        byte[] ciphertextTagBytes = new byte[symmetricEncryptionResult.ciphertext().length];
//        System.arraycopy(ciphertextBytes, 0, ciphertextTagBytes, 0, ciphertextBytes.length);
//        System.arraycopy(tagBytes, 0, ciphertextTagBytes, ciphertextBytes.length, tagBytes.length);


        SymmetricEncryptionBase64 symmetricEncryptionBase64 = getEncodedResult(symmetricEncryptionResult);

        System.out.println("Key: " + symmetricEncryptionBase64.key());
        System.out.println("IV: " + symmetricEncryptionBase64.iv());
        System.out.println("CipherText: " + symmetricEncryptionBase64.ciphertext());
        System.out.println("Algo: " + symmetricEncryptionBase64.symmetricAlgorithm());

    }

    @Test
    public void decryptForPython() throws Exception {

        byte[] ciphertextBytes = Base64.getDecoder().decode("YIet5Qm5pVAp0OE=".getBytes());
        byte[] tagBytes = Base64.getDecoder().decode("domWmLMuCSt6y0XXrfNCzA==".getBytes());
        byte[] ciphertextTagBytes = new byte[ciphertextBytes.length + tagBytes.length];
        System.arraycopy(ciphertextBytes, 0, ciphertextTagBytes, 0, ciphertextBytes.length);
        System.arraycopy(tagBytes, 0, ciphertextTagBytes, ciphertextBytes.length, tagBytes.length);


        SymmetricEncryptionResultGCM symmetricEncryption = new SymmetricEncryptionResultGCM(Base64.getDecoder().decode("T0IAEhGf5MwKcK6V".getBytes()),
                Base64.getDecoder().decode("KaYzQ+Rhcoapa9KSqwaV9w==".getBytes()),
                ciphertextTagBytes,
                null,
                SymmetricAlgorithm.DEFAULT);

        SymmetricDecryptionResult symmetricDecryptionResult = symmetricWrapperGCM.decrypt(symmetricEncryption);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }*/
}
