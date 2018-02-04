package com.crypterac.card;

import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CrypteracAppletIT extends TestCase {

    public void testSelect() throws IOException {
        String output = executeCommand("java -cp lib/jcardsim-2.2.2-all.jar:target/crypterac-1.0.0-SNAPSHOT.jar" +
                " com.licel.jcardsim.utils.APDUScriptTool jcardsim.cfg public_address.script \n");

        String[] arr = output.split("Le:");
        output = arr[arr.length - 1].split("SW1:")[0].replace(", ", "").substring(3);
        // Check if the public address is correct
        assertEquals(new String(Hex.decode(output)), new String(CrypteracApplet.PUBLIC_KEY));
    }

    private String executeCommand(String command) {
        StringBuffer output = new StringBuffer();

        Process p;
        try {
            p = Runtime.getRuntime().exec(command);
            p.waitFor();
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line;
            while ((line = reader.readLine())!= null) {
                output.append(line + "\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return output.toString();

    }
}