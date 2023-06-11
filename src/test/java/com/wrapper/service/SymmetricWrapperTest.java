package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.symmetric.config.SymmetricEncryptionConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryption;
import com.wrapper.symmetric.models.SymmetricEncryption;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionGCM;
import com.wrapper.symmetric.service.SymmetricWrapper;
import com.wrapper.symmetric.service.SymmetricWrapperGCM;
import com.wrapper.symmetric.utils.Utility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.wrapper.symmetric.utils.Utility.getEncodedResult;


@SpringBootTest(classes = {Application.class})
public class SymmetricWrapperTest {

    @Autowired
    private SymmetricWrapper symmetricWrapper;

    @Autowired
    private SymmetricWrapperGCM symmetricWrapperGCM;

    @Autowired
    private SymmetricEncryptionConfig symmetricEncryptionConfig;


    @Test
    public void testSymmetricEncryptionUsingAllDefaults() throws Exception {

        SymmetricEncryption symmetricEncryptionResult = symmetricWrapper.encrypt("Hello World".getBytes());
        SymmetricDecryption symmetricDecryptionResult = symmetricWrapper.decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testSymmetricEncryptionUsingDefaultAlgorithm() throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(SymmetricAlgorithm.DEFAULT));
        kg.init(Utility.getAlgorithmBytes(SymmetricAlgorithm.DEFAULT));
        SecretKey secretKey = kg.generateKey();


        SymmetricEncryption symmetricEncryptionResult = symmetricWrapper.encrypt(secretKey, "Hello World 121@#".getBytes());
        SymmetricDecryption symmetricDecryptionResult = symmetricWrapper.decrypt(symmetricEncryptionResult);


        Assertions.assertEquals("Hello World 121@#", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingDefaultKey() throws Exception {


        SymmetricEncryption symmetricEncryptionResult = symmetricWrapper.encrypt(SymmetricAlgorithm.AES_GCM_256_NoPadding, "1232F #$$^%$^ Hello World".getBytes());
        SymmetricDecryption symmetricDecryptionResult = symmetricWrapper.decrypt(symmetricEncryptionResult);

        Assertions.assertEquals("1232F #$$^%$^ Hello World", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    public void testSymmetricEncryptionUsingKeyLoading() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_192_PKCS5Padding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryption symmetricEncryptionResult = symmetricWrapper.encrypt(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding, secretKey, plainText);

        SymmetricDecryption symmetricDecryptionResult = symmetricWrapper.decrypt(symmetricEncryptionResult);


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

        SymmetricEncryptionGCM symmetricEncryptionResult = symmetricWrapperGCM.encrypt(SymmetricAlgorithm.AES_GCM_128_NoPadding, secretKey, plainText, associatedData);

        SymmetricDecryption symmetricDecryptionResult = symmetricWrapperGCM.decrypt(symmetricEncryptionResult);


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void xyz() throws Exception {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_CBC_256_PKCS5Padding;

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getAlgorithmBytes(symmetricAlgorithm));
        SecretKey secretKey = kg.generateKey();

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);


        SymmetricEncryption symmetricEncryptionResult = symmetricWrapper.encrypt(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding, secretKey, plainText);

        SymmetricEncryptionBase64 symmetricEncryptionBase64 = getEncodedResult(symmetricEncryptionResult);

        System.out.println("Key: " + symmetricEncryptionBase64.key());
        System.out.println("IV: " + symmetricEncryptionBase64.iv());
        System.out.println("CipherText: " + symmetricEncryptionBase64.ciphertext());
        System.out.println("Algo: " + symmetricEncryptionBase64.symmetricAlgorithm());

        SymmetricDecryption symmetricDecryptionResult = symmetricWrapper.decrypt(symmetricEncryptionResult);

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void qwe() throws Exception {


        SymmetricEncryption symmetricEncryption = new SymmetricEncryption(Base64.getDecoder().decode("y13rLPg4iiceQ7IR".getBytes()),
                Base64.getDecoder().decode("FFJb+NUVfxVMYMoA0G9kPw==".getBytes()),
                Base64.getDecoder().decode("P/F2ITe93OmlKBE=".getBytes()),
                SymmetricAlgorithm.DEFAULT);

        SymmetricDecryption symmetricDecryptionResult = symmetricWrapper.decrypt(symmetricEncryption);

        Assertions.assertEquals("Hello World JCA WRAPPER", new String(symmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }

}
