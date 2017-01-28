package org.shayalon.config;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

public class AppConfig {

    private static final Config config = ConfigFactory.load().getConfig("sec_01");

    private static final Config algoConfig = config.getConfig("algo");
    public static final String cryptAlgo = algoConfig.getString("cryptAlgo");
    public static final String signatureAlgo = algoConfig.getString("signatureAlgo");
    public static final String symmetricCipherAlgo = algoConfig.getString("symmetricCipherAlgo");
    public static final String asymmetricCipherAlgo = algoConfig.getString("asymmetricCipherAlgo");
    public static final int cryptAlgoKeySize = algoConfig.getInt("cryptAlgoKeySize");
    public static final String signatureProvider = algoConfig.getString("signatureProvider");

    private static final Config keystoreConfig = config.getConfig("keystore");
    public static final String keystorePath = keystoreConfig.getString("path");
    public static final String keystorePassword = keystoreConfig.getString("password");

    private static final Config configConfig = config.getConfig("config");
    public static final String configPath = configConfig.getString("path");

    private static final Config encryptConfig = config.getConfig("encrypt");
    public static final String plainTextFile = encryptConfig.getString("plainTextFile");
    public static final String encryptOutputFile = encryptConfig.getString("outputFile");
    public static final String encryptPrivateKeyAlias = encryptConfig.getString("privateKeyAlias");
    public static final String encryptPrivateKeyPassword = encryptConfig.getString("privateKeyPassword");
    public static final String encryptPublicKeyAlias = encryptConfig.getString("publicKeyAlias");

    private static final Config decryptConfig = config.getConfig("decrypt");
    public static final String encryptedFile = decryptConfig.getString("encryptedFile");
    public static final String decryptOutputFile = decryptConfig.getString("outputFile");
    public static final String decryptPrivateKeyAlias = decryptConfig.getString("privateKeyAlias");
    public static final String decryptPrivateKeyPassword = decryptConfig.getString("privateKeyPassword");
    public static final String decryptPublicKeyAlias = decryptConfig.getString("publicKeyAlias");

}
