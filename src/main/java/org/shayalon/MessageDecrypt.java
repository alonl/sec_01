package org.shayalon;

import org.shayalon.models.Configuration;
import org.shayalon.utils.EncTools;
import org.shayalon.utils.XmlTools;

public class MessageDecrypt {

    public static void main(String[] args) throws Exception {
        Configuration configuration = Configuration.fromXml(XmlTools.readFile("config.xml"));
        EncTools.decryptAndVerifySignature(configuration);
    }

}
