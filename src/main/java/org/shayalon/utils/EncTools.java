package org.shayalon.utils;

import javax.crypto.*;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;


public class EncTools {

    public void encryptAndSign() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException, NoSuchProviderException, SignatureException, BadPaddingException, IllegalBlockSizeException, TransformerException, ParserConfigurationException {

        String clearTextFile = "plaintext.txt";
        String cipherTextFile = "plaintext.txt.enc";
        String configurationFile = "config.xml";

        String cryptAlgo = "AES";
        String signatureAlgo = "SHA1withRSA";
        String symmetricCipherAlgo = "AES/CBC/NoPadding";
        String asymmetricCipherAlgo = "RSA";
        int cryptAlgoKeySize = 128;
        String signatureProvider = "SunRsaSign";

        String keystoreName = "/usr/lib/jvm/java-8-oracle/jre/lib/security/cacerts";
        String keystorePassword = "changeit";
        String keyAlias = "bubua";
        String keyPassword = "bubuapass";
        String publicKeyAlias = "bubub";

        SecretKey secretKey = createEncryptionKey(cryptAlgo, cryptAlgoKeySize);
        Cipher cipher = createCipher(symmetricCipherAlgo, secretKey);
        KeyStore keyStore = getKeystore(keystoreName, keystorePassword);
        PrivateKey privateKey = getPrivateKeyFromKeystore(keyStore, keyAlias, keyPassword);
        Signature signature = createSignature(signatureAlgo, privateKey, signatureProvider);
        encryptAndSignFile(cipher, signature, clearTextFile, cipherTextFile);

        PublicKey publicKey = getPublicKeyFromKeystore(keyStore, publicKeyAlias);

        byte[] encryptedCipherKey = encryptSecretKey(asymmetricCipherAlgo, publicKey, secretKey);
        byte[] fileSignature = signature.sign();
        createConfigurationFile(configurationFile, encryptedCipherKey, fileSignature);
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

    private Cipher createCipher(String cipherAlgo, SecretKey secretKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
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

    private Signature createSignature(String signatureAlgo, PrivateKey privateKey, String provider) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance(signatureAlgo, provider);
        signature.initSign(privateKey);
        return signature;
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
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }

            if (cipherOutputStream != null) {
                cipherOutputStream.close();
            }
        }
    }

    private byte[] encryptSecretKey(String cipherAlgo, PublicKey publicKey, SecretKey secretKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }


    private void createConfigurationFile(String outputFile, byte[] encryptedSecretKey, byte[] fileSignature) throws TransformerException, ParserConfigurationException {
        XmlTools.writeConfigurationFile(outputFile, new String(encryptedSecretKey), new String(fileSignature));
    }
}