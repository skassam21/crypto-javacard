package com.crypterac.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;


/**
 * @noinspection ClassNamePrefixedWithPackageName, ImplicitCallToSuper, MethodOverridesStaticMethodOfSuperclass, ResultOfObjectAllocationIgnored
 */
public class HelloWorld extends Applet {
    private static final byte[] PUBLIC_KEY = {'0', 'x', '0', '4', '1', 'f', 'F', 'A', 'a', 'B', '7',
            '1', '6', 'D', 'F', '5', '6', '7', 'A', '3', '1', 'f', 'b', '9', '6', '7', '3', 'D', '0',
            '6', '4', '5', 'D', '0', '8', 'E', 'b', '7', 'E', '6', 'c', '1'};

    protected HelloWorld() {
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorld();
    }

    /**
     * @noinspection UnusedDeclaration
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            // For the select command, send the publicAddress
            sendPublicKey(apdu);
        }
    }

    private void sendPublicKey( APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short length = (short) PUBLIC_KEY.length;
        Util.arrayCopyNonAtomic(PUBLIC_KEY, (short)0, buffer, (short)0, length);
        apdu.setOutgoingAndSend((short)0, length);
    }
}