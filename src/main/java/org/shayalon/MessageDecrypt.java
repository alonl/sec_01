package org.shayalon;

import org.shayalon.models.Configuration;
import org.shayalon.utils.EncTools;
import org.shayalon.utils.XmlTools;

import static org.shayalon.config.AppConfig.configPath;

public class MessageDecrypt {

    public static void main(String[] args) {
        try {
            Configuration configuration = Configuration.fromXml(XmlTools.readFile(configPath));
            boolean isSignatureVerified = EncTools.decryptAndVerifySignature(configuration);
            if (isSignatureVerified) {
                System.out.println("File decrypted SUCCESSFULLY.");
            } else {
                System.out.println("ERROR: INVALID SIGNATURE");
            }
        } catch (Exception e) {
            System.out.println("Error occurred:");
            e.printStackTrace();
        }
    }

}
