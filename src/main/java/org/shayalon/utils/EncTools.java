package org.shayalon.utils;

import org.shayalon.models.Configuration;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

import static org.shayalon.config.AppConfig.*;

/**
 * Encryption tools functions
 */
public class EncTools {

    /**
     * Encrypts a file and signs it. See application.conf for configuration options.
     *
     * @return A Configuration object, with signature, encrypted secret key and encrypted IV, to be passed with the encrypted file.
     */
    public static Configuration encryptAndSign() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException, NoSuchProviderException, SignatureException, BadPaddingException, IllegalBlockSizeException, TransformerException, ParserConfigurationException {
        SecretKey secretKey = generateSecretKey(cryptAlgo, cryptAlgoKeySize);
        Cipher cipher = createEncryptionCipher(symmetricCipherAlgo, secretKey);
        KeyStore keyStore = getKeystore(keystorePath, keystorePassword);
        PrivateKey privateKey = getPrivateKeyFromKeystore(keyStore, encryptPrivateKeyAlias, encryptPrivateKeyPassword);
        Signature signature = createSignature(signatureAlgo, signatureProvider);
        signature.initSign(privateKey);
        encryptAndSignFile(cipher, signature, plainTextFile, encryptOutputFile);

        PublicKey publicKey = getPublicKeyFromKeystore(keyStore, encryptPublicKeyAlias);

        byte[] fileSignature = signature.sign();
        byte[] encryptedSecretKey = encryptBuffer(asymmetricCipherAlgo, publicKey, secretKey.getEncoded());
        byte[] encryptedIv = encryptBuffer(asymmetricCipherAlgo, publicKey, cipher.getIV());
        return new Configuration(fileSignature, encryptedSecretKey, encryptedIv);
    }

    /**
     * Decrypts a file and verifies its signature. See application.conf for configuration options.
     * If the signature is invalid, outputs an ERROR to the output file.
     *
     * @param configuration A Configuration object, with signature, encrypted secret key and encrypted IV, to be passed with the encrypted file.
     * @return true if the signature is valid, false otherwise
     */
    public static boolean decryptAndVerifySignature(Configuration configuration) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException, InvalidAlgorithmParameterException {
        byte[] signatureBuffer = configuration.getSignature();
        byte[] encryptedSecretKey = configuration.getEncryptedSecretKey();
        byte[] encryptedIv = configuration.getEncryptedIv();

        KeyStore keyStore = getKeystore(keystorePath, keystorePassword);
        PrivateKey privateKey = getPrivateKeyFromKeystore(keyStore, decryptPrivateKeyAlias, decryptPrivateKeyPassword);

        byte[] decryptedSecretKeyBuffer = decryptBuffer(asymmetricCipherAlgo, privateKey, encryptedSecretKey);
        byte[] decryptedIv = decryptBuffer(asymmetricCipherAlgo, privateKey, encryptedIv);

        SecretKey secretKey = new SecretKeySpec(decryptedSecretKeyBuffer, cryptAlgo);
        Cipher cipher = createDecryptCipher(symmetricCipherAlgo, secretKey, decryptedIv);

        PublicKey publicKey = getPublicKeyFromKeystore(keyStore, decryptPublicKeyAlias);
        Signature signature = createSignature(signatureAlgo, signatureProvider);
        signature.initVerify(publicKey);

        boolean isSignatureVerified = verifySignature(cipher, signature, signatureBuffer, encryptedFile);
        if (!isSignatureVerified) {
            try (PrintWriter out = new PrintWriter(decryptOutputFile)) {
                out.println("ERROR: INVALID SIGNATURE");
            }
            return false;
        }

        decryptFile(cipher, encryptedFile, decryptOutputFile);
        return true;
    }

    /**
     * Retrieves private key from a keystore
     *
     * @param keyStore
     * @param keyAlias
     * @param keyPassword
     * @return the private key
     */
    private static PrivateKey getPrivateKeyFromKeystore(KeyStore keyStore, String keyAlias, String keyPassword) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
        return pkEntry.getPrivateKey();
    }

    /**
     * Retrieves public key from a keystore
     *
     * @param keyStore
     * @param keyAlias
     * @return the public key
     */
    private static PublicKey getPublicKeyFromKeystore(KeyStore keyStore, String keyAlias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        return keyStore.getCertificate(keyAlias).getPublicKey();
    }

    /**
     * Generates a random secret key
     *
     * @param cryptAlgo
     * @param cryptAlgoKeySize
     * @return the secret key
     */
    private static SecretKey generateSecretKey(String cryptAlgo, int cryptAlgoKeySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(cryptAlgo);
        keyGen.init(cryptAlgoKeySize);
        return keyGen.generateKey();
    }

    /**
     * Creates an encryption cipher
     *
     * @param cipherAlgo
     * @param secretKey
     * @return the cipher
     */
    private static Cipher createEncryptionCipher(String cipherAlgo, SecretKey secretKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher;
    }

    /**
     * Creates a decryption cipher
     *
     * @param cipherAlgo
     * @param secretKey
     * @param iv
     * @return the cipher
     */
    private static Cipher createDecryptCipher(String cipherAlgo, SecretKey secretKey, byte[] iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher;
    }

    /**
     * Retrieves a keystore
     *
     * @param keystoreName
     * @param keystorePassword
     * @return the keystore
     */
    private static KeyStore getKeystore(String keystoreName, String keystorePassword) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] password = keystorePassword.toCharArray();
        java.io.FileInputStream keystoreFis = null;
        try {
            keystoreFis = new java.io.FileInputStream(keystoreName);
            ks.load(keystoreFis, password);
        } finally {
            if (keystoreFis != null) {
                keystoreFis.close();
            }
        }
        return ks;
    }

    /**
     * Creates a signature
     *
     * @param signatureAlgo
     * @param provider
     * @return the signature
     */
    private static Signature createSignature(String signatureAlgo, String provider) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        return Signature.getInstance(signatureAlgo, provider);
    }

    /**
     * Encrypts a file and signs it
     *
     * @param cipher
     * @param signature
     * @param inputPath
     * @param outputPath
     */
    private static void encryptAndSignFile(Cipher cipher, Signature signature, String inputPath, String outputPath) throws SignatureException, IOException {
        BufferedInputStream inputStream = null;
        CipherOutputStream cipherOutputStream = null;
        try {
            inputStream = new BufferedInputStream(new FileInputStream(inputPath));
            cipherOutputStream = new CipherOutputStream(new FileOutputStream(outputPath), cipher);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = inputStream.read(buffer)) >= 0) {
                signature.update(buffer, 0, len);
                cipherOutputStream.write(buffer, 0, len);
            }
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
            if (cipherOutputStream != null) {
                cipherOutputStream.close();
            }
        }
    }

    /**
     * Verified a signature of a file
     *
     * @param cipher
     * @param signature
     * @param signatureBuffer
     * @param inputPath
     * @return
     */
    private static boolean verifySignature(Cipher cipher, Signature signature, byte[] signatureBuffer, String inputPath) throws SignatureException, IOException {
        CipherInputStream cipherInputStream = null;
        try {
            cipherInputStream = new CipherInputStream(new FileInputStream(inputPath), cipher);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = cipherInputStream.read(buffer)) >= 0) {
                signature.update(buffer, 0, len);
            }
        } finally {
            if (cipherInputStream != null) {
                cipherInputStream.close();
            }
        }
        return signature.verify(signatureBuffer);
    }

    /**
     * Decrypts a file
     *
     * @param cipher
     * @param inputPath
     * @param outputPath
     */
    private static void decryptFile(Cipher cipher, String inputPath, String outputPath) throws SignatureException, IOException {
        CipherInputStream cipherInputStream = null;
        BufferedOutputStream bufferedOutputStream = null;
        try {
            cipherInputStream = new CipherInputStream(new FileInputStream(inputPath), cipher);
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputPath));
            byte[] buffer = new byte[1024];
            int len;
            while ((len = cipherInputStream.read(buffer)) >= 0) {
                bufferedOutputStream.write(buffer, 0, len);
            }
        } finally {
            if (cipherInputStream != null) {
                cipherInputStream.close();
            }
            if (bufferedOutputStream != null) {
                bufferedOutputStream.close();
            }
        }
    }

    /**
     * Encrypts an arbitrary byte array buffer
     *
     * @param cipherAlgo
     * @param publicKey
     * @param buffer
     * @return
     */
    private static byte[] encryptBuffer(String cipherAlgo, PublicKey publicKey, byte[] buffer) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(buffer);
    }

    /**
     * Decrypts an arbitrary byte array buffer
     *
     * @param cipherAlgo
     * @param privateKey
     * @param encryptedSecretKey
     * @return
     */
    private static byte[] decryptBuffer(String cipherAlgo, PrivateKey privateKey, byte[] encryptedSecretKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSecretKey);
    }

}