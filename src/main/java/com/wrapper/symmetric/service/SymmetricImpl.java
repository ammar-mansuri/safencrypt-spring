package com.wrapper.symmetric.service;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.symmetric.utils.Utility;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.text.MessageFormat;
import java.util.Base64;
import java.util.Objects;
import java.util.Random;

@Service
public class SymmetricImpl {

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;
    private final SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;
    private final SymmetricConfig symmetricConfig;

    private final SymmetricKeyStore symmetricKeyStore;

    @Autowired
    public SymmetricImpl(SymmetricConfig symmetricConfig, SymmetricInteroperabilityConfig symmetricInteroperabilityConfig, SymmetricKeyStore symmetricKeyStore) {
        this.symmetricConfig = symmetricConfig;
        this.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
        this.symmetricKeyStore = symmetricKeyStore;
    }

    @SneakyThrows
    protected SymmetricEncryptionBase64 interoperableEncrypt(SymmetricInteroperableBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        if (!isAlgorithmSecure(symmetricAlgorithm.getLabel())) {
            throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", languageDetails.symmetric().defaultAlgo()));
        }

//        languageDetails.libraryProvider();
//        languageDetails.symmetric().defaultAlgo();
//        languageDetails.symmetric().ivBytes();
//        languageDetails.symmetric().keyBytes();
//        languageDetails.symmetric().encoding();
//        languageDetails.symmetric().Resultant();

        SecretKey secretKey = SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm);

        SymmetricEncryptionResult symmetricEncryptionResult;

        if (isGCM(symmetricAlgorithm)) {
            symmetricEncryptionResult = encryptWithGCM(symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        } else {
            symmetricEncryptionResult = encrypt(Integer.valueOf(languageDetails.symmetric().ivBytes()), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText());
        }

        String alias = "alias_" + System.currentTimeMillis();
        symmetricKeyStore.saveKey(alias, secretKey);
        return Utility.getSymmetricEncodedResult(symmetricEncryptionResult, alias);

    }

    @SneakyThrows
    protected SymmetricDecryptionResult interoperableDecrypt(SymmetricInteroperableBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        SymmetricEncryptionResult symmetricEncryptionResult;

        byte[] cipherBytes;

        if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {

            byte[] ciphertextBytes = Base64.getDecoder().decode(symmetricBuilder.getCipherText());
            byte[] tagBytes = Base64.getDecoder().decode(symmetricBuilder.getAssociatedData());
            cipherBytes = new byte[ciphertextBytes.length + tagBytes.length];
            System.arraycopy(ciphertextBytes, 0, cipherBytes, 0, ciphertextBytes.length);
            System.arraycopy(tagBytes, 0, cipherBytes, ciphertextBytes.length, tagBytes.length);

        } else {

            cipherBytes = Base64.getDecoder().decode(symmetricBuilder.getCipherText());
        }

        symmetricEncryptionResult = new SymmetricEncryptionResult(
                Base64.getDecoder().decode(symmetricBuilder.getIv()),
                symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()).getEncoded(),
                cipherBytes,
                symmetricAlgorithm);

        return decrypt(symmetricEncryptionResult, symmetricBuilder.getAssociatedData());

    }

    @SneakyThrows
    protected SymmetricEncryptionResult encrypt(SymmetricBuilder symmetricBuilder) {

        if (!isAlgorithmSecure(symmetricBuilder.getSymmetricAlgorithm().getLabel())) {
            throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", symmetricBuilder.getSymmetricAlgorithm().getLabel()));
        }

        SecretKey secretKey = symmetricBuilder.getKey();

        if (!isKeyDefined(symmetricBuilder)) {

            secretKey = SymmetricKeyGenerator.generateSymmetricKey(symmetricBuilder.getSymmetricAlgorithm());
        }

        if (isGCM(symmetricBuilder.getSymmetricAlgorithm())) {
            return encryptWithGCM(symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        }

        return encrypt(symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlainText());
    }


    private SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) throws Exception {

        return encrypt(REST_IV_SIZE, symmetricAlgorithm, secretKey, plaintext);
    }

    @SneakyThrows
    private SymmetricEncryptionResult encrypt(int IV_LENGTH, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) {


        Cipher cipher;

        try {
            cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm), "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", symmetricAlgorithm.getLabel()));
            }
        }


        final IvParameterSpec ivSpec = generateIv(IV_LENGTH);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        final byte[] ciphertext = cipher.doFinal(plaintext);
        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));

    }


    @SneakyThrows
    private SymmetricEncryptionResult encryptWithGCM(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) {

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIv(GCM_IV_SIZE);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    @SneakyThrows
    protected SymmetricDecryptionResult decrypt(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) {

        if (!isAlgorithmSecure(symmetricEncryptionResult.symmetricAlgorithm().getLabel())) {
            throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", symmetricEncryptionResult.symmetricAlgorithm().getLabel()));
        }

        return isGCM(symmetricEncryptionResult.symmetricAlgorithm()) ? decryptWithGCM(symmetricEncryptionResult, associatedData) : decryptRest(symmetricEncryptionResult);
    }

    private SymmetricDecryptionResult decryptRest(final SymmetricEncryptionResult symmetricEncryptionResult) throws Exception {

        Cipher cipher;

        try {
            cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()), "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", symmetricEncryptionResult.symmetricAlgorithm().getLabel()));
            }
        }


        final SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(symmetricEncryptionResult.iv()));

        final byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());

        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }

    private SymmetricDecryptionResult decryptWithGCM(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) throws Exception {

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        final SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), Utility.getSimpleAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, symmetricEncryptionResult.iv()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());


        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }


    private boolean isGCM(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().startsWith("AES_GCM");
    }

    private boolean isKeyDefined(SymmetricBuilder symmetricBuilder) {
        return symmetricBuilder.getKey() != null && symmetricBuilder.getKey().getEncoded().length > 0;
    }

    private IvParameterSpec generateIv(int IV_LENGTH) {

        final byte[] iv = new byte[IV_LENGTH];
        final Random random = new SecureRandom();
        random.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        return ivSpec;
    }

    public boolean isAlgorithmSecure(String symmetricAlgorithm) {
        return symmetricConfig.algorithms().contains(symmetricAlgorithm);
    }


}
