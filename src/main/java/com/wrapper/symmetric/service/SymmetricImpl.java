package com.wrapper.symmetric.service;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionBase64;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import com.wrapper.utils.Utility;
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
import java.util.Objects;
import java.util.Random;

@Service
public class SymmetricImpl {

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;

    private final SymmetricKeyGenerator symmetricKeyGenerator;
    private final SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;
    private final SymmetricConfig symmetricConfig;

    @Autowired
    public SymmetricImpl(SymmetricConfig symmetricConfig, SymmetricInteroperabilityConfig symmetricInteroperabilityConfig, SymmetricKeyGenerator symmetricKeyGenerator) {
        this.symmetricConfig = symmetricConfig;
        this.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
        this.symmetricKeyGenerator = symmetricKeyGenerator;
    }

    @SneakyThrows
    protected SymmetricEncryptionBase64 interoperableEncrypt(SymmetricBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperability());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.getlanguageDetails(symmetricBuilder.getSymmetricInteroperability().name());

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


        return Utility.getSymmetricEncodedResult(encrypt(Integer.valueOf(languageDetails.symmetric().ivBytes()), symmetricAlgorithm, symmetricKeyGenerator.generateSymmetricKeyInternal(symmetricAlgorithm), symmetricBuilder.getPlaintext()));

    }

    @SneakyThrows
    protected SymmetricEncryptionResult encrypt(SymmetricBuilder symmetricBuilder) {

        if (!isAlgorithmSecure(symmetricBuilder.getSymmetricAlgorithm().getLabel())) {
            throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", symmetricBuilder.getSymmetricAlgorithm().getLabel()));
        }

        SecretKey secretKey = symmetricBuilder.getKey();

        if (!isKeyDefined(symmetricBuilder)) {

//            KeyGenerator kg = KeyGenerator.getInstance(Utility.getSimpleAlgorithm(symmetricBuilder.getSymmetricAlgorithm()));
//            kg.init(Utility.getAlgorithmBytes(symmetricBuilder.getSymmetricAlgorithm()));
            secretKey = symmetricKeyGenerator.generateSymmetricKeyInternal(symmetricBuilder.getSymmetricAlgorithm());
        }

        if (isGCM(symmetricBuilder.getSymmetricAlgorithm())) {
            return encryptWithGCM(symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlaintext(), symmetricBuilder.getAssociatedData());
        }

        return encrypt(symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlaintext());
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

        final Cipher cipher = Cipher.getInstance(Utility.getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

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
