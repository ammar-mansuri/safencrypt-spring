package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.enums.SymmetricInteroperability;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.service.SymmetricBuilder;
import com.wrapper.symmetric.service.SymmetricImpl;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import com.wrapper.symmetric.service.SymmetricKeyStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


@SpringBootTest(classes = {Application.class})
public class SymmetricImplTest {

    @Autowired
    private SymmetricImpl symmetricImpl;

    @Autowired
    private SymmetricKeyStore symmetricKeyStore;

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

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGCMWithOutAuthenticationTag() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingGCMWithAuthenticationTag() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
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


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();


        byte[] associatedDataModified = "First test using AEADD".getBytes(StandardCharsets.UTF_8);

        Assertions.assertThrows(AEADBadTagException.class, () -> {
            SymmetricBuilder.createDecryptionBuilder()
                    .optionalAssociatedData(associatedDataModified)
                    .decrypt(symmetricEncryptionResult);
        });

    }


    @Test
    public void encryptForPython() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        byte[] plainText = "Hello World JCA WRAPPER Encrypt For Python".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionResult symmetricEncryptionResult = SymmetricBuilder.createEncryptionBuilder(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                .key(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm))
                .plaintext(plainText)
                .encrypt();

        /*SymmetricEncryptionBase64 symmetricEncryptionBase64 = getSymmetricEncodedResult(symmetricEncryptionResult);

        System.out.println("Key: " + symmetricEncryptionBase64.key());
        System.out.println("IV: " + symmetricEncryptionBase64.iv());
        System.out.println("CipherText: " + symmetricEncryptionBase64.ciphertext());
        System.out.println("Algo: " + symmetricEncryptionBase64.symmetricAlgorithm());*/

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

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testSymmetricInteroperabilityWithCSharp() {

        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricBuilder
                .createInteroperableEncryptionBuilder(SymmetricInteroperability.CSharp)
                .plaintext("TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8))
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }

    @Test
    public void testSymmetricEncryptionInteroperabilityWithPython() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricBuilder
                .createInteroperableEncryptionBuilder(SymmetricInteroperability.Python)
                .plaintext(plainText)
                .encrypt();

        System.out.println(symmetricEncryptionResult.toString());
    }

    @Test
    public void testSymmetricEncryptionDecryptionInteroperabilityWithPython() {

        byte[] plainText = "Checking Interoperability of a Keystore".getBytes();

        SymmetricEncryptionBase64 symmetricEncryptionResult = SymmetricBuilder
                .createInteroperableEncryptionBuilder(SymmetricInteroperability.Python)
                .plaintext(plainText)
                .encrypt();

        SymmetricEncryptionResult symmetricDecryptionInput = new SymmetricEncryptionResult(
                Base64.getDecoder().decode(symmetricEncryptionResult.iv()),
                symmetricKeyStore.loadKey(symmetricEncryptionResult.keyAlias()).getEncoded(),
                Base64.getDecoder().decode(symmetricEncryptionResult.ciphertext()),
                symmetricEncryptionResult.symmetricAlgorithm());

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricDecryptionInput);

        Assertions.assertEquals("Checking Interoperability of a Keystore", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));
    }

    @Test
    public void testSymmetricDecryptionInteroperabilityWithPython() {

        byte[] cipherText = Base64.getDecoder().decode("znhGsJ7RywwYCVqTS9MlD7tcC8qSUTK0XSusJRGki3G/t1O2WgJnTwDPTIoMUVUW".getBytes());
        byte[] iv = Base64.getDecoder().decode("xtdTk3LA8bLDoiGoyNjeAw==".getBytes());

        SymmetricEncryptionResult symmetricEncryptionResult = new SymmetricEncryptionResult(
                iv,
                symmetricKeyStore.loadKey("alias_1687143719446").getEncoded(),
                cipherText,
                SymmetricAlgorithm.AES_CBC_256_PKCS5Padding);

        SymmetricDecryptionResult symmetricDecryptionResult = SymmetricBuilder.createDecryptionBuilder()
                .decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("TU Clausthal Located in Clausthal Zellerfeld", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));
    }


}
