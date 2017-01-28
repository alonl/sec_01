package org.shayalon;

import org.shayalon.models.Configuration;
import org.shayalon.utils.XmlTools;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;

public class App2 {
    public static void main(String[] args) {
        try {
            Configuration x = Configuration.fromXml(XmlTools.readFile("output/config.xml"));
            System.out.println(x);
        } catch (ParserConfigurationException | SAXException | IOException | TransformerException e) {
            e.printStackTrace();
        }
    }
}
