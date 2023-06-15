package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.enums.SymmetricInteroperability;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class SymmetricBuilder {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SymmetricInteroperability symmetricInteroperability;
    private SecretKey key;
    private byte[] plaintext;
    private byte[] associatedData;

    private static SymmetricBuilder encryption;

    private SymmetricImpl symmetricImpl;

    private SymmetricBuilder() {
        // private constructor to enforce the use of builder pattern
    }

    @Autowired
    private SymmetricBuilder(SymmetricImpl symmetricImpl) {
        encryption = new SymmetricBuilder();
        this.symmetricImpl = symmetricImpl;
    }

    @PostConstruct
    public void init() {
        encryption.symmetricImpl = symmetricImpl;
    }

    public SymmetricAlgorithm getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public SymmetricInteroperability getSymmetricInteroperability() {
        return symmetricInteroperability;
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
        encryption = new SymmetricBuilder(encryption.symmetricImpl);
        return new KeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static KeyBuilder createEncryptionBuilder(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SymmetricBuilder(encryption.symmetricImpl);
        return new KeyBuilder(encryption, symmetricAlgorithm);
    }

    public static InteroperableEncryptionBuilder createInteroperableEncryptionBuilder(SymmetricInteroperability symmetricInteroperability) {
        encryption = new SymmetricBuilder(encryption.symmetricImpl);
        return new InteroperableEncryptionBuilder(encryption, symmetricInteroperability);
    }

    public static CiphertextBuilder createDecryptionBuilder() {
        encryption = new SymmetricBuilder(encryption.symmetricImpl);
        return new CiphertextBuilder(encryption);
    }

    public static class KeyBuilder {
        private SymmetricBuilder encryption;

        private KeyBuilder(SymmetricBuilder encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
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
        private SymmetricBuilder encryption;

        private PlaintextBuilder(SymmetricBuilder encryption) {
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
            return encryption.symmetricImpl.encrypt(encryption);
        }
    }


    public static class CiphertextBuilder {
        private SymmetricBuilder encryption;

        private CiphertextBuilder(SymmetricBuilder encryption) {
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

            return encryption.symmetricImpl.decrypt(symmetricEncryptionResult, encryption.getAssociatedData());
        }
    }

    public static class InteroperableEncryptionBuilder {
        private SymmetricBuilder encryption;

        private InteroperableEncryptionBuilder(SymmetricBuilder encryption, SymmetricInteroperability symmetricInteroperability) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperability = symmetricInteroperability;
        }

        public InteroperablePlaintextBuilder plaintext(byte[] plaintext) {
            encryption.plaintext = plaintext;
            return new InteroperablePlaintextBuilder(encryption);
        }
    }

    public static class InteroperablePlaintextBuilder {
        private SymmetricBuilder encryption;

        private InteroperablePlaintextBuilder(SymmetricBuilder encryption) {
            this.encryption = encryption;
        }

        public InteroperablePlaintextBuilder optionalAssociatedData(byte[] associatedData) throws Exception {

            if (!encryption.symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new Exception("Associated Data can only be SET for algorithm AES_GCM");
            }

            encryption.associatedData = associatedData;
            return new InteroperablePlaintextBuilder(encryption);
        }

        @SneakyThrows
        public SymmetricEncryptionBase64 encrypt() {
            return encryption.symmetricImpl.interoperableEncrypt(encryption);
        }
    }
}
