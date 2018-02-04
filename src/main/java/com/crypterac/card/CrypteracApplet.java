package com.crypterac.card;

import javacard.framework.*;

public class CrypteracApplet extends Applet {
    public static final byte[] PUBLIC_KEY = {'0', 'x', '0', '4', '1', 'f', 'F', 'A', 'a', 'B', '7',
            '1', '6', 'D', 'F', '5', '6', '7', 'A', '3', '1', 'f', 'b', '9', '6', '7', '3', 'D', '0',
            '6', '4', '5', 'D', '0', '8', 'E', 'b', '7', 'E', '6', 'c', '1'};

    private byte[] echoBytes;
    private byte[] initParamsBytes;
    private final byte[] transientMemory;
    private static final short LENGTH_ECHO_BYTES = 256;

    protected CrypteracApplet(byte[] bArray, short bOffset, byte bLength) {
        echoBytes = new byte[LENGTH_ECHO_BYTES];
        if (bLength > 0) {
            byte iLen = bArray[bOffset]; // aid length
            bOffset = (short) (bOffset + iLen + 1);
            byte cLen = bArray[bOffset]; // info length
            bOffset = (short) (bOffset + 3);
            byte aLen = bArray[bOffset]; // applet data length
            initParamsBytes = new byte[aLen];
            Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1), initParamsBytes, (short) 0, aLen);
        }
        transientMemory = JCSystem.makeTransientByteArray(LENGTH_ECHO_BYTES, JCSystem.CLEAR_ON_RESET);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CrypteracApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            // For the select command, send the publicAddress
            sendPublicKey(apdu);
        }
    }

    private void sendPublicKey(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short length = (short) PUBLIC_KEY.length;
        Util.arrayCopyNonAtomic(PUBLIC_KEY, (short)0, buffer, (short)0, length);
        apdu.setOutgoingAndSend((short)0, length);
    }
}