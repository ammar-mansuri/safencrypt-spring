package com.wrapper.symmetric.service;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.builder.SymmetricEncryptionBuilder;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricDecryptionResult;
import com.wrapper.symmetric.models.SymmetricEncryptionResult;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.text.MessageFormat;
import java.util.HashSet;

import static com.wrapper.symmetric.utils.Utility.*;

@Service
public class SymmetricImpl {

    private static final int GCM_TAG_LENGTH = 96;
    private static final int GCM_IV_SIZE = 12;
    private static final int REST_IV_SIZE = 16;
    private final SymmetricConfig symmetricConfig;

    private final SymmetricKeyStore symmetricKeyStore;

    @Autowired
    public SymmetricImpl(SymmetricConfig symmetricConfig, SymmetricKeyStore symmetricKeyStore) {
        this.symmetricConfig = symmetricConfig;
        this.symmetricKeyStore = symmetricKeyStore;
    }


    @SneakyThrows
    public SymmetricEncryptionResult encrypt(SymmetricEncryptionBuilder symmetricBuilder) {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(symmetricBuilder.getSymmetricAlgorithm().getLabel());

        isAlgorithmSecure(symmetricAlgorithm.getLabel());

        SecretKey secretKey = symmetricBuilder.getKey();

        if (!isKeyDefined(symmetricBuilder)) {
            secretKey = SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm);
        }

        if (isGCM(symmetricAlgorithm)) {
            return encryptWithGCM(GCM_TAG_LENGTH, GCM_IV_SIZE, symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        }

        checkKeyLength(secretKey, symmetricAlgorithm);

        return encrypt(symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlainText());
    }

    private SymmetricEncryptionResult encrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) {

        return encrypt(REST_IV_SIZE, symmetricAlgorithm, secretKey, plaintext);
    }

    @SneakyThrows
    protected SymmetricEncryptionResult encrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) {


        Cipher cipher;

        try {
            cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm), "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", symmetricAlgorithm.getLabel()));
            }
        }


        final IvParameterSpec ivSpec = generateIv(ivSize);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        final byte[] ciphertext = cipher.doFinal(plaintext);
        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));

    }


    @SneakyThrows
    protected SymmetricEncryptionResult encryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) {

        final Cipher cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIv(ivSize);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricEncryptionResult(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    @SneakyThrows
    protected SymmetricDecryptionResult decrypt(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) {
        SymmetricAlgorithm algorithm = symmetricEncryptionResult.symmetricAlgorithm();
        isAlgorithmSecure(algorithm.getLabel());
        return isGCM(algorithm) ?
                decryptWithGCM(symmetricEncryptionResult, associatedData) : decryptRest(symmetricEncryptionResult);
    }

    @SneakyThrows
    private SymmetricDecryptionResult decryptRest(final SymmetricEncryptionResult symmetricEncryptionResult) {

        Cipher cipher;

        try {
            cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()), "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", symmetricEncryptionResult.symmetricAlgorithm().getLabel()));
            }
        }


        final SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(symmetricEncryptionResult.iv()));

        final byte[] plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());

        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }

    @SneakyThrows
    private SymmetricDecryptionResult decryptWithGCM(final SymmetricEncryptionResult symmetricEncryptionResult, byte[] associatedData) {

        final Cipher cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricEncryptionResult.symmetricAlgorithm()));

        final SecretKey secretKey = new SecretKeySpec(symmetricEncryptionResult.key(), getKeyAlgorithm(symmetricEncryptionResult.symmetricAlgorithm()));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, symmetricEncryptionResult.iv()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }
        final byte[] plaintext;

        try {
            plaintext = cipher.doFinal(symmetricEncryptionResult.ciphertext());
        } catch (AEADBadTagException e) {
            throw new SafencryptException("Tag Mismatch: The associated data used for encryption is different", e);
        }


        return new SymmetricDecryptionResult(plaintext, symmetricEncryptionResult.symmetricAlgorithm());
    }


    @SneakyThrows
    public SymmetricDecryptionResult decrypt(SymmetricEncryptionBuilder symmetricBuilder) {

        checkKeyLength(symmetricBuilder.getKey(), symmetricBuilder.getSymmetricAlgorithm());
        SymmetricAlgorithm algorithm = symmetricBuilder.getSymmetricAlgorithm();
        isAlgorithmSecure(algorithm.getLabel());
        return isGCM(algorithm) ? decryptWithGCM(symmetricBuilder) : decryptRest(symmetricBuilder);
    }

    @SneakyThrows
    private SymmetricDecryptionResult decryptRest(final SymmetricEncryptionBuilder encryptionBuilder) {
        Cipher cipher;
        String algorithm = getAlgorithmForCipher(encryptionBuilder.getSymmetricAlgorithm());
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(algorithm, "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is currently not supported", encryptionBuilder.getSymmetricAlgorithm().getLabel()));
            }
        }
        final SecretKey secretKey = new SecretKeySpec(encryptionBuilder.getKey().getEncoded(), getKeyAlgorithm(encryptionBuilder.getSymmetricAlgorithm()));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionBuilder.getIv()));
        final byte[] plaintext = cipher.doFinal(encryptionBuilder.getCipherText());
        return new SymmetricDecryptionResult(plaintext, encryptionBuilder.getSymmetricAlgorithm());
    }

    private SymmetricDecryptionResult decryptWithGCM(final SymmetricEncryptionBuilder encryptionBuilder) throws Exception {
        final Cipher cipher = Cipher.getInstance(getAlgorithmForCipher(encryptionBuilder.getSymmetricAlgorithm()));
        final SecretKey secretKey = new SecretKeySpec(encryptionBuilder.getKey().getEncoded(), getKeyAlgorithm(encryptionBuilder.getSymmetricAlgorithm()));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, encryptionBuilder.getIv()));
        final byte[] associatedData = encryptionBuilder.getAssociatedData();
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        final byte[] plaintext;
        try {
            plaintext = cipher.doFinal(encryptionBuilder.getCipherText());
        } catch (AEADBadTagException e) {
            throw new SafencryptException("Tag Mismatch: The Associated Data/IV used for encryption is different", e);
        }
        return new SymmetricDecryptionResult(plaintext, encryptionBuilder.getSymmetricAlgorithm());
    }

    @SneakyThrows
    protected void isAlgorithmSecure(String symmetricAlgorithm) {
        if (!symmetricConfig.algorithms().contains(symmetricAlgorithm)) {
            throw new SafencryptException(MessageFormat.format("Selected Algorithm [{0}] is not SET as SECURE in defined configuration", symmetricAlgorithm));
        }
    }

    @SneakyThrows
    protected void checkKeyLength(SecretKey secretKey, SymmetricAlgorithm symmetricAlgorithm) {

        final int keyLength = secretKey.getEncoded().length * 8;
        HashSet<Integer> allowedKeyLength = new HashSet<>() {{
            add(128);
            add(192);
            add(256);
        }};

        if (!allowedKeyLength.contains(keyLength)) {
            throw new SafencryptException(MessageFormat.format("Provided Key With Length [{0}] bits is not compatible with selected algorithm [{1}] ", keyLength, symmetricAlgorithm.getLabel()));
        }

    }

}
