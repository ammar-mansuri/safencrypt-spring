package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class SymmetricEncryptionBuilder {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SecretKey key;
    private byte[] plaintext;
    private byte[] associatedData;

    private static SymmetricEncryptionBuilder encryption;

    private SymmetricWrapper symmetricWrapper;

    private SymmetricEncryptionBuilder() {
        // private constructor to enforce the use of builder pattern
    }

    @Autowired
    private SymmetricEncryptionBuilder(SymmetricWrapper symmetricWrapper) {
        encryption = new SymmetricEncryptionBuilder();
        this.symmetricWrapper = symmetricWrapper;
    }

    @PostConstruct
    public void init() {
        encryption.symmetricWrapper = symmetricWrapper;
    }

    public SymmetricAlgorithm getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public SecretKey getKey() {
        return key;
    }

    public byte[] getPlaintext() {
        return plaintext;
    }

    public byte[] getAssociatedData() {
        return associatedData;
    }

    public static KeyBuilder createEncryptionBuilder() {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricWrapper);
        return new KeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static KeyBuilder createEncryptionBuilder(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricWrapper);
        return new KeyBuilder(encryption, symmetricAlgorithm);
    }

    public static CiphertextBuilder createDecryptionBuilder() {
        encryption = new SymmetricEncryptionBuilder(encryption.symmetricWrapper);
        return new CiphertextBuilder(encryption);
    }

    public static class KeyBuilder {
        private SymmetricEncryptionBuilder encryption;

        private KeyBuilder(SymmetricEncryptionBuilder encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        public KeyBuilder key(SecretKey key) {
            encryption.key = key;
            return this;
        }

        public PlaintextBuilder plaintext(byte[] plaintext) {
            encryption.plaintext = plaintext;
            return new PlaintextBuilder(encryption);
        }
    }

    public static class PlaintextBuilder {
        private SymmetricEncryptionBuilder encryption;

        private PlaintextBuilder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        public PlaintextBuilder optionalAssociatedData(byte[] associatedData) throws Exception {

            if (!encryption.symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new Exception("Associated Data can only be SET for algorithm AES_GCM");
            }

            encryption.associatedData = associatedData;
            return new PlaintextBuilder(encryption);
        }

        @SneakyThrows
        public SymmetricEncryptionResult encrypt() {
            return encryption.symmetricWrapper.encrypt(encryption);
        }
    }


    public static class CiphertextBuilder {
        private SymmetricEncryptionBuilder encryption;

        private CiphertextBuilder(SymmetricEncryptionBuilder encryption) {
            this.encryption = encryption;
        }

        public CiphertextBuilder optionalAssociatedData(byte[] associatedData) {

            encryption.associatedData = associatedData;
            return this;
        }

        @SneakyThrows
        public SymmetricDecryptionResult decrypt(SymmetricEncryptionResult symmetricEncryptionResult) {

            if (encryption.associatedData != null && !symmetricEncryptionResult.symmetricAlgorithm().getLabel().startsWith("AES_GCM")) {
                throw new Exception("Associated Data can only be SET for algorithm AES_GCM");
            }

            return encryption.symmetricWrapper.decrypt(symmetricEncryptionResult, encryption.getAssociatedData());
        }
    }
}
