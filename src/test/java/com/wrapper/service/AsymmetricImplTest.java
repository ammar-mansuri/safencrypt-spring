package com.wrapper.service;

import com.wrapper.Application;
import com.wrapper.asymmetric.models.AsymmetricDecryptionResult;
import com.wrapper.asymmetric.models.AsymmetricEncryptionResult;
import com.wrapper.asymmetric.service.AsymmetricImpl;
import com.wrapper.asymmetric.service.AsymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;


@SpringBootTest(classes = {Application.class})
public class AsymmetricImplTest {

    @Autowired
    private AsymmetricImpl asymmetricImpl;

    @Test
    public void testAsymmetricEncryptionUsingAllDefaults() {

        AsymmetricEncryptionResult asymmetricEncryptionResult = asymmetricImpl.encrypt("Hello World".getBytes(StandardCharsets.UTF_8));

        AsymmetricDecryptionResult asymmetricDecryptionResult = asymmetricImpl.decrypt(asymmetricEncryptionResult);

        Assertions.assertEquals("Hello World", new String(asymmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    public void testAsymmetricEncryptionUsingDefaultAlgorithm() {

        AsymmetricEncryptionResult asymmetricEncryptionResult = asymmetricImpl.encrypt(AsymmetricKeyGenerator.generateAsymmetricKey(), "Hello World 121@#".getBytes(StandardCharsets.UTF_8));

        AsymmetricDecryptionResult asymmetricDecryptionResult = asymmetricImpl.decrypt(asymmetricEncryptionResult);

        Assertions.assertEquals("Hello World 121@#", new String(asymmetricDecryptionResult.plainText(), StandardCharsets.UTF_8));

    }


}
