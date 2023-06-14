package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import lombok.SneakyThrows;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class SymmetricEncryption {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SecretKey key;
    private byte[] plaintext;
    private byte[] associatedData;

    private static SymmetricEncryption encryption;

    private SymmetricWrapper symmetricWrapper;


    private SymmetricEncryption() {
        // private constructor to enforce the use of builder pattern
        this.symmetricWrapper = new SymmetricWrapper();
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
        return new KeyBuilder(SymmetricAlgorithm.DEFAULT);
    }

    public static KeyBuilder createEncryptionBuilder(SymmetricAlgorithm symmetricAlgorithm) {
        return new KeyBuilder(symmetricAlgorithm);
    }

    public static CiphertextBuilder createDecryptionBuilder() {
        encryption = new SymmetricEncryption();
        return new CiphertextBuilder(encryption);
    }

    public static class KeyBuilder {
        private SymmetricEncryption encryption;

        private KeyBuilder(SymmetricAlgorithm symmetricAlgorithm) {
            encryption = new SymmetricEncryption();
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
        private SymmetricEncryption encryption;

        private PlaintextBuilder(SymmetricEncryption encryption) {
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
        private SymmetricEncryption encryption;

        private CiphertextBuilder(SymmetricEncryption encryption) {
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
