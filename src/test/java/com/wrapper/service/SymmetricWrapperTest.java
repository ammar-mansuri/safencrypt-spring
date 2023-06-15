package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.symmetric.config.InteroperabilitySymmetricEncryptionConfig;
import com.wrapper.symmetric.config.SymmetricEncryptionConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.utils.Utility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.wrapper.symmetric.utils.Utility.getEncodedResult;


@SpringBootTest(classes = {Application.class})
public class SymmetricWrapperTest {


    @Autowired
    private SymmetricEncryptionConfig symmetricEncryptionConfig;

    @Autowired
    private InteroperabilitySymmetricEncryptionConfig interoperabilitySymmetricEncryptionConfig;

    @Test
    public void testSymmetricEncryptionUsingAllDefaults() throws Exception {

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder()
                .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testSymmetricEncryptionUsingDefaultAlgorithm() throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(SymmetricAlgorithm.DEFAULT));
        kg.init(Utility.getAlgorithmBytes(SymmetricAlgorithm.DEFAULT));
        SecretKey secretKey = kg.generateKey();


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder()
                .key(secretKey)
                .plaintext("Hello World 121@#".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals("Hello World 121@#", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingDefaultKey() throws Exception {


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .plaintext("1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
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


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                .key(secretKey)
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
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

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
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


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
                .optionalAssociatedData(associatedData)
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingInsecureAlgorithm() throws Exception {

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_128_NoPadding)
                    .plaintext("Hello World".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });

    }


    @Test
    public void testSymmetricEncryptionUsingGCMWithTagMismatch() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        Assertions.assertThrows(AEADBadTagException.class, () -> {
            SymmetricEncryptionBuilder.createDecryptionBuilder()
                    .optionalAssociatedData(associatedDataModified)
                    .decrypt(symmetricEncryptionResult);
        });

    }


    @Test
    public void encryptForPython() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER Encrypt For Python".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricEncryptionBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .key(secretKey)
                .plaintext(plainText)
                .encrypt();

        SymmetricEncryptionBase64 symmetricEncryptionBase64 = getEncodedResult(symmetricEncryptionResult);

        System.out.println("Key: " + symmetricEncryptionBase64.key());
        System.out.println("IV: " + symmetricEncryptionBase64.iv());
        System.out.println("CipherText: " + symmetricEncryptionBase64.ciphertext());
        System.out.println("Algo: " + symmetricEncryptionBase64.symmetricAlgorithm());

    }

    @Test
    public void decryptFromPython() {

        byte[] ciphertextBytes = Base64.getDecoder().decode("lJipwcZuQ+0no1s=".getBytes());
        byte[] tagBytes = Base64.getDecoder().decode("ypgsDoaFKGj06ljQ".getBytes());
        byte[] ciphertextTagBytes = new byte[ciphertextBytes.length + tagBytes.length];
        System.arraycopy(ciphertextBytes, 0, ciphertextTagBytes, 0, ciphertextBytes.length);
        System.arraycopy(tagBytes, 0, ciphertextTagBytes, ciphertextBytes.length, tagBytes.length);

        SymmetricEncryptionResult symmetricEncryptionResult = new SymmetricEncryptionResult(Base64.getDecoder().decode("MXA8iL1gvl6i7Qx6".getBytes()),
                Base64.getDecoder().decode("2Gn4xCkAioEBk21QY9BWCw==".getBytes()),
                ciphertextTagBytes,
                SymmetricAlgorithm.AES_GCM_128_NoPadding);

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricEncryptionBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }
}
