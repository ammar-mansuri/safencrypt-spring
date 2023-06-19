package com.wrapper.asymmetric.service;

import com.wrapper.asymmetric.config.AsymmetricConfig;
import com.wrapper.asymmetric.enums.AsymmetricAlgorithm;
import com.wrapper.asymmetric.models.AsymmetricDecryptionResult;
import com.wrapper.asymmetric.models.AsymmetricEncryptionResult;
import com.wrapper.asymmetric.utils.Utility;
import com.wrapper.exceptions.SafencryptException;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.text.MessageFormat;

@Service
public class AsymmetricImpl {


    //    private final ASymmetricInteroperabilityConfig aSymmetricInteroperabilityConfig;
    private final AsymmetricConfig aSymmetricConfig;


    public AsymmetricImpl(AsymmetricConfig aSymmetricConfig) {
        this.aSymmetricConfig = aSymmetricConfig;
    }

    public AsymmetricEncryptionResult encrypt(byte[] plaintext) {
        return encrypt(AsymmetricKeyGenerator.generateAsymmetricKey(AsymmetricAlgorithm.DEFAULT), plaintext);
    }

    public AsymmetricEncryptionResult encrypt(KeyPair keyPair, byte[] plaintext) {
        return encrypt(AsymmetricAlgorithm.DEFAULT, keyPair, plaintext);
    }

    @SneakyThrows
    public AsymmetricEncryptionResult encrypt(AsymmetricAlgorithm asymmetricAlgorithm, KeyPair keyPair, byte[] plaintext) {

        Cipher cipher;

        try {
            cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(asymmetricAlgorithm));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(asymmetricAlgorithm), "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", asymmetricAlgorithm.getLabel()));
            }
        }

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new AsymmetricEncryptionResult(keyPair, ciphertext, asymmetricAlgorithm);

    }

    @SneakyThrows
    public AsymmetricDecryptionResult decrypt(AsymmetricEncryptionResult asymmetricEncryptionResult) {

        Cipher cipher;

        try {
            cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(asymmetricEncryptionResult.asymmetricAlgorithm()));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(asymmetricEncryptionResult.asymmetricAlgorithm()), "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", asymmetricEncryptionResult.asymmetricAlgorithm().getLabel()));
            }
        }

        cipher.init(Cipher.DECRYPT_MODE, asymmetricEncryptionResult.keyPair().getPrivate());

        byte[] plainText = cipher.doFinal(asymmetricEncryptionResult.ciphertext());

        return new AsymmetricDecryptionResult(plainText, asymmetricEncryptionResult.asymmetricAlgorithm());
    }
}
