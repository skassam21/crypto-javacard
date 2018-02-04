package com.crypterac.card;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class CrypteracAppletIT extends TestCase {

    private static final String TEST_APPLET_AID = "010203040506070809";

    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        System.clearProperty("com.licel.jcardsim.card.applet.0.AID");
        System.clearProperty("com.licel.jcardsim.card.applet.0.Class");
    }

    public void testSelect() {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create(TEST_APPLET_AID);
        simulator.installApplet(appletAID, CrypteracApplet.class);

        // 3. select applet
        simulator.selectApplet(appletAID);

        // 4. send select APDU
        CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0,
                Hex.decode(TEST_APPLET_AID));
        ResponseAPDU response = simulator.transmitCommand(selectApplet);

        // 5. check response
        assertEquals(0x9000, response.getSW());
    }
}