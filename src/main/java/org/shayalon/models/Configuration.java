package org.shayalon.models;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.util.Base64;

public class Configuration {

    private byte[] signature;
    private byte[] encryptedSecretKey;
    private final byte[] encryptedIv;

    private static final String SIGNATURE = "signature";
    private static final String ENCRYPTED_SECRET_KEY = "encryptedSecretKey";
    private static final String ENCRYPTED_IV = "encryptedIv";

    public static Configuration fromXml(Document doc) throws ParserConfigurationException, IOException, SAXException, TransformerException {
        Element root = doc.getDocumentElement();
        root.normalize();

        String base64Signature = root.getElementsByTagName(SIGNATURE).item(0).getTextContent();
        String base64EncryptedSecretKey = root.getElementsByTagName(ENCRYPTED_SECRET_KEY).item(0).getTextContent();
        String base64Iv = root.getElementsByTagName(ENCRYPTED_IV).item(0).getTextContent();

        byte[] signature = Base64.getDecoder().decode(base64Signature);
        byte[] encryptedSecretKey = Base64.getDecoder().decode(base64EncryptedSecretKey);
        byte[] iv = Base64.getDecoder().decode(base64Iv);

        return new Configuration(signature, encryptedSecretKey, iv);
    }

    public Document toXml() throws ParserConfigurationException {
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        String base64EncryptedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKey);
        String base64Iv = Base64.getEncoder().encodeToString(encryptedIv);

        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element rootElement = doc.createElement(this.getClass().getSimpleName());
        doc.appendChild(rootElement);

        Element signatureElem = doc.createElement(SIGNATURE);
        signatureElem.appendChild(doc.createTextNode(base64Signature));
        rootElement.appendChild(signatureElem);

        Element secretKeyElem = doc.createElement(ENCRYPTED_SECRET_KEY);
        secretKeyElem.appendChild(doc.createTextNode(base64EncryptedSecretKey));
        rootElement.appendChild(secretKeyElem);

        Element ivElem = doc.createElement(ENCRYPTED_IV);
        ivElem.appendChild(doc.createTextNode(base64Iv));
        rootElement.appendChild(ivElem);

        return doc;
    }

    public Configuration(byte[] signature, byte[] encryptedSecretKey, byte[] encryptedIv) {
        this.signature = signature;
        this.encryptedSecretKey = encryptedSecretKey;
        this.encryptedIv = encryptedIv;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getEncryptedSecretKey() {
        return encryptedSecretKey;
    }

    public byte[] getEncryptedIv() {
        return encryptedIv;
    }

    @Override
    public String toString() {
        return "Configuration{" + System.lineSeparator() +
                "  signature=" + Base64.getEncoder().encodeToString(signature) + System.lineSeparator() +
                "  encryptedSecretKey=" + Base64.getEncoder().encodeToString(encryptedSecretKey) + System.lineSeparator() +
                '}';
    }

}
