package org.shayalon;

import org.shayalon.models.Configuration;
import org.shayalon.utils.EncTools;
import org.shayalon.utils.XmlTools;

import static org.shayalon.config.AppConfig.configPath;

public class MessageEncrypt {
    public static void main(String[] args) {
        try {
            Configuration configuration = EncTools.encryptAndSign();
            System.out.println("File encrypted SUCCESSFULLY.");
            XmlTools.writeFile(configuration.toXml(), configPath);
        } catch (Exception e) {
            System.out.println("Error occurred:");
            e.printStackTrace();
        }
    }
}
