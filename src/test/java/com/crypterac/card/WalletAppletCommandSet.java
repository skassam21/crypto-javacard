package com.crypterac.card;

import javacard.framework.ISO7816;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * This class is used to send APDU to the applet. Each method corresponds to an APDU as defined in the APPLICATION.md
 * file. Some APDUs map to multiple methods for the sake of convenience since their payload or response require some
 * pre/post processing.
 */
public class WalletAppletCommandSet {
  public static final String APPLET_AID = "53746174757357616C6C6574417070";
  public static final byte[] APPLET_AID_BYTES = Hex.decode(APPLET_AID);

  private final CardChannel apduChannel;

  private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


  public WalletAppletCommandSet(CardChannel apduChannel) {
    this.apduChannel = apduChannel;
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public ResponseAPDU select() throws CardException {

    CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, APPLET_AID_BYTES);
    return apduChannel.transmit(selectApplet);
  }

  public ResponseAPDU loadKey(ECKeyPair ecKeyPair) throws CardException {
    byte[] publicKey = ecKeyPair.getPublicKey().toByteArray();
    byte[] privateKey = ecKeyPair.getPrivateKey().toByteArray();

    int pubLen = publicKey.length;
    int pubOff = 0;

    if(publicKey[0] == 0x00) {
      pubOff++;
      pubLen--;
    }

    byte[] ansiPublic = new byte[pubLen + 1];
    ansiPublic[0] = 0x04;
    System.arraycopy(publicKey, pubOff, ansiPublic, 1, pubLen);

    return loadKey(ansiPublic, privateKey);
  }

  public ResponseAPDU loadKey(byte[] publicKey, byte[] privateKey) throws CardException {
    int privLen = privateKey.length;
    int privOff = 0;

    if(privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    int off = 0;
    int totalLength = publicKey.length + 1;
    totalLength += (privLen + 1);

    byte[] data = new byte[totalLength];

    data[off++] = (byte) publicKey.length;
    System.arraycopy(publicKey, 0, data, off, publicKey.length);
    off += publicKey.length;

    data[off++] = (byte) privLen;
    System.arraycopy(privateKey, privOff, data, off, privLen);

    return loadKey(data);
  }

  public ResponseAPDU loadKey(byte[] data) throws CardException {
    CommandAPDU loadKeyApplet =  new CommandAPDU(ISO7816.CLA_ISO7816,  WalletApplet.INS_LOAD_KEY, 0, 0, data);
    return apduChannel.transmit(loadKeyApplet);
  }

  public ResponseAPDU exportKey() throws CardException {
    CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, WalletApplet.INS_EXPORT_KEY, 0, 0);
    return apduChannel.transmit(selectApplet);
  }

  /**
   * Sends a SIGN APDU. The dataType is P1 as defined in the applet. The isFirst and isLast arguments are used to form
   * the P2 parameter. The data is the data to sign, or part of it. Only when sending the last block a signature is
   * generated and thus returned. When signing a precomputed hash it must be done in a single block, so isFirst and
   * isLast will always be true at the same time.
   *
   * @param data the data to sign
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU sign(byte[] data) throws CardException {
    CommandAPDU signApplet =  new CommandAPDU(ISO7816.CLA_ISO7816,  WalletApplet.INS_SIGN, 0, 0, data);
    return apduChannel.transmit(signApplet);
  }
}
