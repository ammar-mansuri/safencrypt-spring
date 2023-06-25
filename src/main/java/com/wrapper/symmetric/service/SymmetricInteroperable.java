package com.wrapper.symmetric.service;

import com.wrapper.symmetric.builder.SymmetricInteroperableBuilder;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.utils.Utility;
import lombok.SneakyThrows;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Objects;

import static com.wrapper.symmetric.utils.Base64Decoder.decodeBase64;
import static com.wrapper.symmetric.utils.Utility.isGCM;

@Component
public class SymmetricInteroperable {

    private final SymmetricConfig symmetricConfig;

    private final SymmetricKeyStore symmetricKeyStore;

    private final SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;

    private final SymmetricImpl symmetric;

    public SymmetricInteroperable(SymmetricConfig symmetricConfig, SymmetricKeyStore symmetricKeyStore, SymmetricInteroperabilityConfig symmetricInteroperabilityConfig, SymmetricImpl symmetric) {
        this.symmetricConfig = symmetricConfig;
        this.symmetricKeyStore = symmetricKeyStore;
        this.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
        this.symmetric = symmetric;
    }

    @SneakyThrows
    public SymmetricEncryptionBase64 interoperableEncrypt(SymmetricInteroperableBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        symmetric.isAlgorithmSecure(symmetricAlgorithm.getLabel());

        SecretKey secretKey = SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm);

        SymmetricEncryptionResult symmetricEncryptionResult;

        if (isGCM(symmetricAlgorithm)) {
            symmetricEncryptionResult = symmetric.encryptWithGCM(languageDetails.symmetric().tagLength(), languageDetails.symmetric().ivBytes(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        } else {
            symmetricEncryptionResult = symmetric.encrypt(languageDetails.symmetric().ivBytes(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText());
        }

        String alias = "alias_" + System.currentTimeMillis();
        symmetricKeyStore.saveKey(alias, secretKey);
        return Utility.getSymmetricEncodedResult(symmetricEncryptionResult, alias);

    }

    @SneakyThrows
    public SymmetricDecryptionResult interoperableDecrypt(SymmetricInteroperableBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        SymmetricEncryptionResult symmetricEncryptionResult;

        byte[] cipherBytes;

        if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {

            byte[] ciphertextBytes = decodeBase64(symmetricBuilder.getCipherText());
            byte[] tagBytes = decodeBase64(symmetricBuilder.getAssociatedData());
            cipherBytes = new byte[ciphertextBytes.length + tagBytes.length];
            System.arraycopy(ciphertextBytes, 0, cipherBytes, 0, ciphertextBytes.length);
            System.arraycopy(tagBytes, 0, cipherBytes, ciphertextBytes.length, tagBytes.length);

        } else {

            cipherBytes = decodeBase64(symmetricBuilder.getCipherText());
        }

        symmetricEncryptionResult = new SymmetricEncryptionResult(
                decodeBase64(symmetricBuilder.getIv()),
                symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()).getEncoded(),
                cipherBytes,
                symmetricAlgorithm);

        return symmetric.decrypt(symmetricEncryptionResult, symmetricBuilder.getAssociatedData());

    }
}
