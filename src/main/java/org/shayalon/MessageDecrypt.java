package org.shayalon;

import org.shayalon.models.Configuration;
import org.shayalon.utils.EncTools;
import org.shayalon.utils.XmlTools;
import org.xml.sax.SAXException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class MessageDecrypt {

    public static void main(String[] args) throws ParserConfigurationException, IOException, SAXException, TransformerException {
        Configuration configuration = Configuration.fromXml(XmlTools.readFile("config.xml"));
        try {
            new EncTools().decryptAndVerifySignature(configuration);
        } catch (CertificateException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException | NoSuchProviderException | SignatureException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

}
