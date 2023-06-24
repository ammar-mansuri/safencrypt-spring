package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.utils.Utility;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

@Service
public class SymmetricKeyGenerator {

    public static SecretKey generateSymmetricKey() {
        return generateSymmetricKey(SymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static SecretKey generateSymmetricKey(SymmetricAlgorithm symmetricAlgorithm) {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getKeyAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getKeySize(symmetricAlgorithm));
        return kg.generateKey();
    }


}
