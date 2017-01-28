package org.shayalon;

import org.shayalon.models.Configuration;
import org.shayalon.utils.EncTools;
import org.shayalon.utils.XmlTools;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class MessageEncrypt {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, KeyStoreException, CertificateException, UnrecoverableEntryException, NoSuchProviderException {
        try {
            Configuration configuration = new EncTools().encryptAndSign();
            XmlTools.writeFile(configuration.toXml(), "output/config.xml");
        } catch (SignatureException | TransformerException | ParserConfigurationException e) {
            e.printStackTrace();
        }
    }
}
