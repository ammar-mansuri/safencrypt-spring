package com.wrapper.symmetric.service;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

import static com.wrapper.symmetric.utils.Utility.isGCM;
import static java.util.Objects.requireNonNull;

@Component
public class SymmetricEncryptionBuilder {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SecretKey key;
    private byte[] plainText;
    private byte[] associatedData;
    private byte[] cipherText;
    private byte[] iv;


    private static SymmetricEncryptionBuilder encryption;

    private SymmetricImpl symmetricImpl;


    private SymmetricEncryptionBuilder() {
        // private constructor to enforce the use of builder pattern
    }

    @Autowired
    private SymmetricEncryptionBuilder(SymmetricImpl symmetricImpl) {
        encryption = new SymmetricEncryptionBuilder();
        this.symmetricImpl = symmetricImpl;
    }

    @PostConstruct
    public void init() {
        encryption.symmetricImpl = symmetricImpl;
    }

    public SymmetricAlgorithm getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public SecretKey getKey() {
        return key;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public byte[] getAssociatedData() {
        return associatedData;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getIv() {
        return iv;
    }

    public static KeyBuilder encryption() {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricImpl);
        return new KeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static PlaintextBuilder encryptWithDefaultKeyGen() {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricImpl);
        return new PlaintextBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static KeyBuilder encryption(SymmetricAlgorithm... symmetricAlgorithm) {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricImpl);
        return new KeyBuilder(encryption, symmetricAlgorithm[0]);
    }

    public static PlaintextBuilder encryptWithDefaultKeyGen(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricImpl);
        return new PlaintextBuilder(encryption, symmetricAlgorithm);
    }

    public static DecryptKeyBuilder decryption() {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricImpl);
        return new DecryptKeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static DecryptKeyBuilder decryption(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricImpl);
        return new DecryptKeyBuilder(encryption, symmetricAlgorithm);
    }

    public static class KeyBuilder {

        private SymmetricEncryptionBuilder encryption;

        private KeyBuilder(SymmetricEncryptionBuilder encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        public PlaintextBuilder key(SecretKey key) {
            requireNonNull(key);
            encryption.key = key;
            return new PlaintextBuilder(encryption);
        }
    }

    public static class PlaintextBuilder {
        private SymmetricEncryptionBuilder encryption;

        private PlaintextBuilder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        private PlaintextBuilder(SymmetricEncryptionBuilder encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }


        @SneakyThrows
        public EncryptionBulder plaintext(byte[] plaintext) {
            requireNonNull(plaintext);
            encryption.plainText = plaintext;
            return new EncryptionBulder(encryption);
        }

        @SneakyThrows
        public EncryptionBulder plaintext(byte[] plaintext, byte[] associatedData) {
            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
            encryption.plainText = plaintext;
            encryption.associatedData = associatedData;
            return new EncryptionBulder(encryption);
        }

    }

    public static class DecryptKeyBuilder {
        private SymmetricEncryptionBuilder encryption;

        private DecryptKeyBuilder(SymmetricEncryptionBuilder encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        public DecryptIVBuilder key(SecretKey key) {
            requireNonNull(key);
            encryption.key = key;
            return new DecryptIVBuilder(encryption);
        }
    }

    public static class DecryptIVBuilder {
        private SymmetricEncryptionBuilder encryption;

        private DecryptIVBuilder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        public CiphertextBuilder iv(byte[] iv) {
            requireNonNull(iv);
            encryption.iv = iv;
            return new CiphertextBuilder(encryption);
        }
    }

    public static class CiphertextBuilder {
        private SymmetricEncryptionBuilder encryption;

        private CiphertextBuilder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public DecryptionBulder cipherText(byte[] cipherText) {
            requireNonNull(cipherText);
            encryption.cipherText = cipherText;
            return new DecryptionBulder(encryption);
        }

        @SneakyThrows
        public DecryptionBulder cipherText(byte[] cipherText, byte[] associatedData) {
            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
            encryption.cipherText = cipherText;
            encryption.associatedData = associatedData;
            return new DecryptionBulder(encryption);
        }

    }

    public static class EncryptionBulder {
        private SymmetricEncryptionBuilder encryption;

        private EncryptionBulder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public SymmetricEncryptionResult encrypt() {
            return encryption.symmetricImpl.encrypt(encryption);
        }
    }

    public static class DecryptionBulder {
        private SymmetricEncryptionBuilder encryption;

        private DecryptionBulder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public SymmetricDecryptionResult decrypt() {
            if (encryption.associatedData != null && !isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
            return encryption.symmetricImpl.decrypt(encryption);
        }
    }
}
