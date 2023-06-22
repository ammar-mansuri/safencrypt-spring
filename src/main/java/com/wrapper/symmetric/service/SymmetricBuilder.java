package com.wrapper.symmetric.service;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.enums.SymmetricInteroperabilityLanguages;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

import static java.util.Objects.requireNonNull;

@Component
public class SymmetricBuilder {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages;
    private SecretKey key;
    private byte[] plainText;
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

    public SymmetricInteroperabilityLanguages getSymmetricInteroperabilityLanguages() {
        return symmetricInteroperabilityLanguages;
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

    public static KeyBuilder createEncryptionBuilder() {
        encryption = new SymmetricBuilder(encryption.symmetricImpl);
        return new KeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static KeyBuilder createEncryptionBuilder(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SymmetricBuilder(encryption.symmetricImpl);
        return new KeyBuilder(encryption, symmetricAlgorithm);
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
            encryption.plainText = plaintext;
            return new PlaintextBuilder(encryption);
        }
    }

    public static class PlaintextBuilder {
        private SymmetricBuilder encryption;

        private PlaintextBuilder(SymmetricBuilder encryption) {
            this.encryption = encryption;
        }


        @SneakyThrows
        public PlaintextBuilder optionalAssociatedData(byte[] associatedData) {

            if (!encryption.symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
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
            requireNonNull(encryption);
            if (encryption.associatedData != null && !symmetricEncryptionResult.symmetricAlgorithm().getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
            }

            return encryption.symmetricImpl.decrypt(symmetricEncryptionResult, encryption.getAssociatedData());
        }
    }

}
