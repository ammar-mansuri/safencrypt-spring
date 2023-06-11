import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.wrapper.Application;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

@Disabled
@SpringBootTest(classes = {Application.class})
public class Hashing {

    @Test
    public void simpleTest() {

        /*Counter c1 = new Counter();
        c1.init(28);
        c1.freeze();*/
    }

    @Test
    public void test_Hashing() throws GeneralSecurityException {


        MacConfig.register();

        KeysetHandle handle = null;

        String msg = "AMMAR";

        Mac macPrimitive = null;
        try {
            macPrimitive = handle.getPrimitive(Mac.class);
        } catch (GeneralSecurityException ex) {
            System.err.println("Cannot create primitive, got error: " + ex);
            System.exit(1);
        }
//        byte[] mac = macPrimitive.computeMac(msg.getBytes());

//        System.err.println(mac.toString());
    }

    @Test
    public void testEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey secretKey = kg.generateKey();


        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(("Ammar is " + "a good boy").getBytes(StandardCharsets.UTF_8));
        System.out.println("Ciphertext: " + ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plaintext = cipher.doFinal(ciphertext);
        String decryptedPlaintext = new String(plaintext, StandardCharsets.UTF_8);

        System.out.println("Plaintext: " + plaintext);

        assert ("Ammar is a good boy").equals(decryptedPlaintext);

    }

    @Test
    public void testTinkSymmetric() throws GeneralSecurityException {

        AeadConfig.register();
        KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM"));

        Aead aead = keysetHandle.getPrimitive(Aead.class);

        byte[] ciphertext = aead.encrypt("Ammar is a good boy".getBytes(StandardCharsets.UTF_8), null);

        byte[] plaintext = aead.decrypt(ciphertext, null);


        assert ("Ammar is a good boy").equals(new String(plaintext, StandardCharsets.UTF_8));

    }

    @Test
    public void testJcaMac() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("wdq".getBytes(), ""));
        mac.doFinal("AMMAR".getBytes());

    }


    @Test
    public void getCipherInfo() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidParameterSpecException {
        System.out.println("https://stackoverflow.com/questions/61456475/get-cipher-mode-and-padding-scheme-from-existing-cipher");

        byte[] keyByte = "12345678901234567890123456789013".getBytes("UTF-8");
        SecretKey secretKey = new SecretKeySpec(keyByte, "AES");


        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // key & algorithm details
        System.out.println("SecretKey Algorithm: " + secretKey.getAlgorithm() + " keylength: " + secretKey.getEncoded().length);
        System.out.println("SecretKey format: " + secretKey.getFormat());
        System.out.println("Cipher Algorithm: " + cipher.getAlgorithm() + " Blocksize: " + cipher.getBlockSize());
        System.out.println("Cipher Parameters: " + cipher.getParameters());
        System.out.println("Cipher Provider: " + cipher.getProvider());
        System.out.println("Cipher Provider getInfo: " + cipher.getProvider().getInfo());
        try {
            System.out.println("Cipher IV: " + bytesToHex(cipher.getIV()) + " IV length: " + cipher.getIV().length);
        } catch (NullPointerException e) {
            System.out.println("cipher IV: Algorithm does not use an IV");
        }
        try {
            System.out.println("Cipher parameters encoded: " + bytesToHex(cipher.getParameters().getEncoded()));
        } catch (NullPointerException e) {
            System.out.println("cipher parameters encoded: not available");
        }
    }

    public static Key loadKey(KeyStore ks, String keyAlias, char[] keyPassword) throws KeyStoreException,
            UnrecoverableKeyException, NoSuchAlgorithmException {
        if (!ks.containsAlias(keyAlias)) {
            throw new UnrecoverableKeyException("Secret key " + keyAlias + " not found in keystore");
        }

        SecretKey ss = new SecretKeySpec(ks.getKey(keyAlias, keyPassword).getEncoded(), "");

        return ks.getKey(keyAlias, keyPassword);
    }

    private static void generateSignature() throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = kpGen.generateKeyPair();

        Signature s = Signature.getInstance("SHA1withDSA");
        s.initSign(keyPair.getPrivate(), new SecureRandom());
        s.update("sda".getBytes());
        s.sign();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }


   /* @SneakyThrows
    private Cipher cipher() throws NoSuchAlgorithmException, NoSuchProviderException {
        return Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    }*/
}
