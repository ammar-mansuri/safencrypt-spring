package com.wrapper.symmetric.builder;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.enums.SymmetricInteroperabilityLanguages;
import com.wrapper.symmetric.models.SymmetricPlain;
import com.wrapper.symmetric.models.SymmetricCipherBase64;
import com.wrapper.symmetric.service.SymmetricImpl;
import com.wrapper.symmetric.service.SymmetricInteroperable;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static java.util.Objects.requireNonNull;

@Component
public class SymmetricInteroperableBuilder {

    private SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages;
    private byte[] plainText;
    private byte[] associatedData;

    private String keyAlias;

    private String iv;
    private String cipherText;
    private String tag;
    private static SymmetricInteroperableBuilder encryption;

    private SymmetricImpl symmetricImpl;

    private SymmetricInteroperable symmetricInteroperable;

    private SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;

    private SymmetricInteroperableBuilder() {
        // private constructor to enforce the use of builder pattern
    }

    @Autowired
    private SymmetricInteroperableBuilder(SymmetricImpl symmetricImpl, SymmetricInteroperable symmetricInteroperable, SymmetricInteroperabilityConfig symmetricInteroperabilityConfig) {
        encryption = new SymmetricInteroperableBuilder();
        this.symmetricImpl = symmetricImpl;
        this.symmetricInteroperable = symmetricInteroperable;
        this.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
    }

    @PostConstruct
    public void init() {
        encryption.symmetricImpl = symmetricImpl;
        encryption.symmetricInteroperable = symmetricInteroperable;
        encryption.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
    }


    public SymmetricInteroperabilityLanguages getSymmetricInteroperabilityLanguages() {
        return symmetricInteroperabilityLanguages;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public byte[] getAssociatedData() {
        return associatedData;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getIv() {
        return iv;
    }

    public String getCipherText() {
        return cipherText;
    }

    public String getTag() {
        return tag;
    }

    public static InteroperableEncryptionBuilder createEncryptionBuilder(SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
        encryption = new SymmetricInteroperableBuilder(encryption.symmetricImpl, encryption.symmetricInteroperable, encryption.symmetricInteroperabilityConfig);
        return new InteroperableEncryptionBuilder(encryption, symmetricInteroperabilityLanguages);
    }

    public static InteroperableDBuilder createDecryptionBuilder(SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
        encryption = new SymmetricInteroperableBuilder(encryption.symmetricImpl, encryption.symmetricInteroperable, encryption.symmetricInteroperabilityConfig);
        return new InteroperableDBuilder(encryption, symmetricInteroperabilityLanguages);
    }


    public static class InteroperableEncryptionBuilder {
        private SymmetricInteroperableBuilder encryption;

        private InteroperableEncryptionBuilder(SymmetricInteroperableBuilder encryption, SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperabilityLanguages = symmetricInteroperabilityLanguages;
        }

        public InteroperablePlaintextBuilder plaintext(byte[] plaintext) {
            requireNonNull(plaintext);
            encryption.plainText = plaintext;
            return new InteroperablePlaintextBuilder(encryption);
        }
    }

    public static class InteroperablePlaintextBuilder {
        private SymmetricInteroperableBuilder encryption;

        private InteroperablePlaintextBuilder(SymmetricInteroperableBuilder encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperablePlaintextBuilder optionalAssociatedData(byte[] associatedData) {


            if (!encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo().startsWith("AES_GCM")) {
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
            }

            encryption.associatedData = associatedData;
            return this;
        }

        @SneakyThrows
        public SymmetricCipherBase64 encrypt() {
            return encryption.symmetricInteroperable.interoperableEncrypt(encryption);
        }
    }

    public static class InteroperableDBuilder {
        private SymmetricInteroperableBuilder encryption;

        private InteroperableDBuilder(SymmetricInteroperableBuilder encryption, SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperabilityLanguages = symmetricInteroperabilityLanguages;
        }

        public InteroperableIVBuilder keyAlias(String keyAlias) {
            encryption.keyAlias = keyAlias;
            return new InteroperableIVBuilder(encryption);
        }

    }

    public static class InteroperableIVBuilder {
        private SymmetricInteroperableBuilder encryption;

        private InteroperableIVBuilder(SymmetricInteroperableBuilder encryption) {
            this.encryption = encryption;
        }

        public InteroperableCiphertextBuilder ivBase64(String iv) {
            encryption.iv = iv;
            return new InteroperableCiphertextBuilder(encryption);
        }

    }

    public static class InteroperableCiphertextBuilder {
        private SymmetricInteroperableBuilder encryption;

        private InteroperableCiphertextBuilder(SymmetricInteroperableBuilder encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder cipherTextBase64(String cipherText) {

            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo());
            if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException("TAG is required in algorithm AES_GCM for decryption");
            }

            encryption.cipherText = cipherText;
            return new InteroperableDecryptionBuilder(encryption);
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder cipherTextAndTagBase64(String cipherText, String tag) {

            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo());
            if (!symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException("TAG is not required in algorithm AES_GCM for decryption");
            }

            encryption.cipherText = cipherText;
            encryption.tag = tag;
            return new InteroperableDecryptionBuilder(encryption);
        }
    }


    public static class InteroperableDecryptionBuilder {
        private SymmetricInteroperableBuilder encryption;

        private InteroperableDecryptionBuilder(SymmetricInteroperableBuilder encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder optionalAssociatedData(byte[] associatedData) {

            if (!encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo().startsWith("AES_GCM")) {
                throw new SafencryptException("Associated Data can only be SET for algorithm AES_GCM");
            }

            encryption.associatedData = associatedData;
            return this;
        }

        @SneakyThrows
        public SymmetricPlain decrypt() {
            return encryption.symmetricInteroperable.interoperableDecrypt(encryption);
        }

    }
}
