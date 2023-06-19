package com.wrapper.asymmetric.service;

import com.wrapper.asymmetric.enums.AsymmetricAlgorithm;
import com.wrapper.asymmetric.utils.Utility;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

@Service
public class AsymmetricKeyGenerator {

    public static KeyPair generateAsymmetricKey() {
        return generateAsymmetricKey(AsymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static KeyPair generateAsymmetricKey(AsymmetricAlgorithm asymmetricAlgorithm) {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Utility.getSimpleAlgorithm(asymmetricAlgorithm));
        SecureRandom secureRandom = new SecureRandom();
        keyPairGenerator.initialize(Utility.getAlgorithmBytes(asymmetricAlgorithm), secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

}
