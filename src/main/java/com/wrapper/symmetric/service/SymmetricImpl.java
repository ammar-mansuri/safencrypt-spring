package com.wrapper.symmetric.service;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.config.ErrorConfig;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricPlain;
import com.wrapper.symmetric.models.SymmetricCipher;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HashSet;

import static com.wrapper.symmetric.utils.Utility.*;

@Slf4j
@Service
public class SymmetricImpl {

    private static final int GCM_TAG_LENGTH = 96;
    private static final int GCM_IV_SIZE = 12;
    private static final int REST_IV_SIZE = 16;
    private final SymmetricConfig symmetricConfig;
    private final ErrorConfig errorConfig;

    @Autowired
    public SymmetricImpl(SymmetricConfig symmetricConfig, ErrorConfig errorConfig) {
        this.symmetricConfig = symmetricConfig;
        this.errorConfig = errorConfig;
    }


    /**
     * Main ENCRYPT Function Call from builder
     *
     * @param symmetricBuilder
     * @return
     */
    @SneakyThrows
    public SymmetricCipher encrypt(SymmetricBuilder symmetricBuilder) {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(symmetricBuilder.getSymmetricAlgorithm().getLabel());


        SecretKey secretKey = symmetricBuilder.getKey();

        if (!isKeyDefined(symmetricBuilder)) {
            secretKey = KeyGenerator.generateSymmetricKey(symmetricAlgorithm);
        }

        if (isGCM(symmetricAlgorithm)) {
            return encryptWithGCM(GCM_TAG_LENGTH, GCM_IV_SIZE, symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        }

        return encrypt(REST_IV_SIZE, symmetricBuilder.getSymmetricAlgorithm(), secretKey, symmetricBuilder.getPlainText());
    }

    /**
     * Main DECRYPT Function Call from builder
     *
     * @param symmetricBuilder
     * @return
     */
    @SneakyThrows
    public SymmetricPlain decrypt(SymmetricBuilder symmetricBuilder) {
        SymmetricAlgorithm algorithm = symmetricBuilder.getSymmetricAlgorithm();
        return isGCM(algorithm) ?
                decryptWithGCM(GCM_TAG_LENGTH, symmetricBuilder.getSymmetricAlgorithm(), symmetricBuilder.getKey(), symmetricBuilder.getIv(), symmetricBuilder.getCipherText(), symmetricBuilder.getAssociatedData()) :
                decrypt(symmetricBuilder.getSymmetricAlgorithm(), symmetricBuilder.getKey(), symmetricBuilder.getIv(), symmetricBuilder.getCipherText());

    }


    @SneakyThrows
    protected SymmetricCipher encrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) {
        log.warn("Usage of Algorithm [{}] is insecure in client-server architecture", getAlgorithmForCipher(symmetricAlgorithm));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        Cipher cipher;

        try {
            cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));
        } catch (NoSuchAlgorithmException e) {

            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm), "BC");
            } catch (Exception ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()), ex);
            }
        }


        final IvParameterSpec ivSpec = generateIv(ivSize);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        final byte[] ciphertext = cipher.doFinal(plaintext);
        return new SymmetricCipher(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));

    }


    @SneakyThrows
    protected SymmetricCipher encryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));

        final IvParameterSpec ivSpec = generateIv(ivSize);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricCipher(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    @SneakyThrows
    protected SymmetricPlain decrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, byte[] cipherText) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        Cipher cipher;
        String algorithm = getAlgorithmForCipher(symmetricAlgorithm);
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(algorithm, "BC");
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            }
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        final byte[] plaintext = cipher.doFinal(cipherText);
        return new SymmetricPlain(plaintext, symmetricAlgorithm);
    }

    protected SymmetricPlain decryptWithGCM(int tagLength, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, byte[] cipherText, byte[] associatedData) throws Exception {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        final byte[] plaintext;
        try {
            plaintext = cipher.doFinal(cipherText);
        } catch (AEADBadTagException e) {
            throw new SafencryptException(errorConfig.message("SAF-002", e));
        }
        return new SymmetricPlain(plaintext, symmetricAlgorithm);
    }

    @SneakyThrows
    protected void isAlgorithmSecure(String symmetricAlgorithm) {
        if (symmetricConfig.algorithms().contains(symmetricAlgorithm))
            return;

        throw new SafencryptException(errorConfig.message("SAF-001", symmetricAlgorithm));
    }

    @SneakyThrows
    protected void isKeyLengthCorrect(SecretKey secretKey, SymmetricAlgorithm symmetricAlgorithm) {

        final int keyLength = secretKey.getEncoded().length * 8;
        HashSet<Integer> allowedKeyLength = new HashSet<>() {{
            add(128);
            add(192);
            add(256);
        }};

        if (!allowedKeyLength.contains(keyLength)) {
            throw new SafencryptException(errorConfig.message("SAF-003", String.valueOf(keyLength), symmetricAlgorithm.getLabel()));
        }

    }
}
