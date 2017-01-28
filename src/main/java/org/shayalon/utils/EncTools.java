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

import static org.shayalon.utils.AppConfig.*;


public class EncTools {

    public Configuration encryptAndSign() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException, NoSuchProviderException, SignatureException, BadPaddingException, IllegalBlockSizeException, TransformerException, ParserConfigurationException {
        SecretKey secretKey = createEncryptionKey(cryptAlgo, cryptAlgoKeySize);
        Cipher cipher = createCipher(symmetricCipherAlgo, Cipher.ENCRYPT_MODE, secretKey);
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

    public boolean decryptAndVerifySignature(Configuration configuration) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException, InvalidAlgorithmParameterException {
        byte[] signatureBuffer = configuration.getSignature();
        byte[] encryptedSecretKey = configuration.getEncryptedSecretKey();
        byte[] encryptedIv = configuration.getEncryptedIv();

        KeyStore keyStore = getKeystore(keystorePath, keystorePassword);
        PrivateKey privateKey = getPrivateKeyFromKeystore(keyStore, decryptPrivateKeyAlias, decryptPrivateKeyPassword);

        byte[] decryptedSecretKeyBuffer = decryptBuffer(asymmetricCipherAlgo, privateKey, encryptedSecretKey);
        byte[] decryptedIv = decryptBuffer(asymmetricCipherAlgo, privateKey, encryptedIv);

        SecretKey secretKey = new SecretKeySpec(decryptedSecretKeyBuffer, cryptAlgo);
        Cipher cipher = createDecryptCipher(symmetricCipherAlgo, Cipher.DECRYPT_MODE, secretKey, decryptedIv);


        PublicKey publicKey = getPublicKeyFromKeystore(keyStore, decryptPublicKeyAlias);
        Signature signature = createSignature(signatureAlgo, signatureProvider);
        signature.initVerify(publicKey);

        decryptFile(cipher, signature, encryptedFile, decryptOutputFile);
        boolean isSignatureVerified = signature.verify(signatureBuffer);
        System.out.println("Signature verified? " + isSignatureVerified);
        return isSignatureVerified;
    }

    private PrivateKey getPrivateKeyFromKeystore(KeyStore keyStore, String keyAlias, String keyPassword) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
        return pkEntry.getPrivateKey();
    }

    private PublicKey getPublicKeyFromKeystore(KeyStore keyStore, String keyAlias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        return keyStore.getCertificate(keyAlias).getPublicKey();
    }

    private SecretKey createEncryptionKey(String cryptAlgo, int cryptAlgoKeySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(cryptAlgo);
        keyGen.init(cryptAlgoKeySize);
        return keyGen.generateKey();
    }

    private Cipher createCipher(String cipherAlgo, int mode, SecretKey secretKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(mode, secretKey);
        return cipher;
    }

    private Cipher createDecryptCipher(String cipherAlgo, int mode, SecretKey secretKey, byte[] iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(mode, secretKey, new IvParameterSpec(iv));
        return cipher;
    }

    private KeyStore getKeystore(String keystoreName, String keystorePassword) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
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

    private Signature createSignature(String signatureAlgo, String provider) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        return Signature.getInstance(signatureAlgo, provider);
    }

    private void encryptAndSignFile(Cipher cipher, Signature signature, String inputPath, String outputPath) throws SignatureException, IOException {
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

    private void decryptFile(Cipher cipher, Signature signature, String inputPath, String outputPath) throws SignatureException, IOException {
        CipherInputStream cipherInputStream = null;
        BufferedOutputStream bufferedOutputStream = null;
        try {
            cipherInputStream = new CipherInputStream(new FileInputStream(inputPath), cipher);
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputPath));
            byte[] buffer = new byte[1024];
            int len;
            while ((len = cipherInputStream.read(buffer)) >= 0) {
                signature.update(buffer, 0, len);
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

    private byte[] encryptBuffer(String cipherAlgo, PublicKey publicKey, byte[] buffer) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(buffer);
    }

    private byte[] decryptBuffer(String cipherAlgo, PrivateKey privateKey, byte[] encryptedSecretKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSecretKey);
    }

}