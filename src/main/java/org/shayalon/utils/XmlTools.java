package org.shayalon.utils;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;

public class XmlTools {

    public static void writeConfigurationFile(String outputFile, String secretKey, String fileSignature) throws ParserConfigurationException, TransformerException {

        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement("configuration");
        doc.appendChild(rootElement);

        Element signatureElem = doc.createElement("signature");
        signatureElem.appendChild(doc.createTextNode(fileSignature));
        rootElement.appendChild(signatureElem);

        Element secretKeyElem = doc.createElement("key");
        secretKeyElem.appendChild(doc.createTextNode(secretKey));
        rootElement.appendChild(secretKeyElem);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(outputFile));

        transformer.transform(source, result);
        System.out.println("File saved!");
    }
}